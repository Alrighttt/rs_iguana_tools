use crate::{now_sec, FIRST_PARTY};
use rusqlite::{params, Connection};
use std::net::Ipv4Addr;

pub fn init_db(conn: &Connection) {
    // Create the "notaries" table if it doesn't already exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notaries (
                  id INTEGER PRIMARY KEY,
                  name TEXT NOT NULL,
                  lastseen INTEGER
                  )",
        params![],
    )
    .unwrap();
    // Create the "ip_logs" table if it doesn't already exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ip_logs (
        ip TEXT NOT NULL PRIMARY KEY,
        notary_id INTEGER,
        first_seen INTEGER,
        last_seen INTEGER,
        FOREIGN KEY(notary_id) REFERENCES notaries(id)
        )",
        params![],
    )
    .unwrap();

    init_notaries_table(&conn, FIRST_PARTY);
    init_ip_bits_dump_table(&conn);
}

pub fn init_notaries_table(conn: &Connection, identities: [&str; 64]) {
    identities.iter().enumerate().for_each(|(x, identity)| {
        conn.execute(
            "INSERT OR IGNORE INTO notaries (id, name, lastseen) values (?1, ?2, ?3)",
            params![x, identity, 0],
        )
        .unwrap();
    });
}

// two tables used to store all IPs shared to us via "ipbits" field
// these IPs could be old notary IPs as they don't seem to be cleaned up
pub fn init_ip_bits_dump_table(conn: &Connection) {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ipbits ( 
        id INTEGER PRIMARY KEY,
        ip TEXT NOT NULL UNIQUE
        )",
        params![],
    )
    .unwrap();

    conn.execute(
        "CREATE TABLE IF NOT EXISTS notary_ipbits (
        notary_id INTEGER,
        ip_id INTEGER,
        first_seen INTEGER,
        last_seen INTEGER,
        PRIMARY KEY(notary_id, ip_id),
        FOREIGN KEY(notary_id) REFERENCES notaries(id),
        FOREIGN KEY(ip_id) REFERENCES ips(id)
        );",
        params![],
    )
    .unwrap();
}

#[test]
fn test_init_db() {
    use crate::FIRST_PARTY;

    let path = "./test.db";
    let conn = Connection::open(path).unwrap();
    init_db(&conn);
    update_lastseen(&conn, 63);
    update_ip_logs(&conn, 63, [1, 1, 1, 1]);
    update_ip_logs(&conn, 63, [1, 2, 3, 4]);
}

pub fn update_ip_logs(conn: &Connection, notary_id: u8, ipbits: [u8; 4]) {
    let ip_str = Ipv4Addr::from(u32::from_be_bytes(ipbits)).to_string();
    let now = now_sec();

    // Check if this server has used this IP before
    let mut stmt = conn
        .prepare("SELECT * FROM ip_logs WHERE notary_id = ? AND ip = ?")
        .unwrap();
    let rows = stmt
        .query_map(params![notary_id, ip_str.clone()], |row| {
            Ok((
                row.get::<_, u8>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, u32>(3)?,
            ))
        })
        .unwrap();

    if rows.count() > 0 {
        // If the server has used this IP before, update the last_seen field
        conn.execute(
            "UPDATE ip_logs SET last_seen = ? WHERE notary_id = ? AND ip = ?",
            params![now, notary_id, ip_str],
        )
        .unwrap();
    } else {
        // If this is a new IP for the server, insert a new row
        conn.execute(
            "INSERT INTO ip_logs (notary_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            params![notary_id, ip_str, now, now],
        )
        .unwrap();
    }
}

pub fn update_known_ips(conn: &Connection, notary_id: u8, ips: Vec<[u8; 4]>) -> Vec<String> {
    let current_timestamp = now_sec();
    let mut new_ips = vec!();

    for ip in ips {
        if ip == [0; 4] {
            continue;
        }
        let ip_str = Ipv4Addr::from(u32::from_be_bytes(ip)).to_string();

        // Insert the IP address into the ips table if it doesn't exist already
        let rows_affected = conn.execute(
            "INSERT OR IGNORE INTO ipbits (ip) VALUES (?)",
            params![ip_str],
        )
        .unwrap();

        // a new IP was inserted into ipbits
        if rows_affected > 0 {
            new_ips.push(ip_str.clone())
        }

        // Get the id of the ip address in the ips table
        let ip_id: i64 = conn
            .query_row(
                "SELECT id FROM ipbits WHERE ip = ?",
                params![ip_str],
                |row| row.get(0),
            )
            .unwrap();

        // Check if this notary/IP combination exists in the notary_ips table
        let mut stmt = conn
            .prepare("SELECT * FROM notary_ipbits WHERE notary_id = ? AND ip_id = ?")
            .unwrap();
        let rows = stmt
            .query_map(params![notary_id, ip_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap();

        if rows.count() > 0 {
            // If the notary/IP combination exists, update the last_seen field
            conn.execute(
                "UPDATE notary_ipbits SET last_seen = ? WHERE notary_id = ? AND ip_id = ?",
                params![current_timestamp, notary_id, ip_id],
            )
            .unwrap();
        } else {
            // If this is a new notary/IP combination, insert a new row with current timestamp as both first_seen and last_seen
            conn.execute(
                "INSERT INTO notary_ipbits (notary_id, ip_id, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                params![notary_id, ip_id, current_timestamp, current_timestamp],
            ).unwrap();
        }
    };
    new_ips
}

pub fn update_lastseen(conn: &Connection, notary_id: u8) {
    conn.execute(
        "UPDATE notaries SET lastseen = ? WHERE id = ?",
        params![now_sec(), notary_id],
    )
    .unwrap();
}
