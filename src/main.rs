use bincode::Options;
use chain::Transaction;
use nanomsg::{Protocol, Socket};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::Read;
use std::net::Ipv4Addr;

use sha2::{Sha256, Digest};
use byteorder::{LittleEndian, WriteBytesExt};

use rusqlite::{params, Connection, Result};
use std::env;

use std::time::{SystemTime, UNIX_EPOCH};

const FIRST_PARTY: [&str; 64] = [
    "blackice_DEV",
    "blackice_AR",
    "alien_EU",
    "alien_NA",
    "alien_SH",
    "alienx_EU",
    "alienx_NA",
    "artem.pikulin_AR",
    "artem.pikulin_DEV",
    "blackice_EU",
    "chmex_AR",
    "chmex_EU",
    "chmex_NA",
    "chmex_SH",
    "chmex1_SH",
    "cipi_1_EU",
    "cipi_2_EU",
    "cipi_AR",
    "cipi_NA",
    "computergenie_EU",
    "computergenie_NA",
    "dimxy_AR",
    "dimxy_DEV",
    "dragonhound_NA",
    "fediakash_AR",
    "gcharang_DEV",
    "gcharang_SH",
    "goldenman_AR",
    "kolo_AR",
    "kolo_EU",
    "kolox_AR",
    "komodopioneers_EU",
    "madmax_DEV",
    "marmarachain_EU",
    "mcrypt_AR",
    "mcrypt_SH",
    "metaphilibert_SH",
    "mylo_NA",
    "mylo_SH",
    "nodeone_NA",
    "nutellalicka_AR",
    "nutellalicka_SH",
    "ocean_AR",
    "pbca26_NA",
    "pbca26_SH",
    "phit_SH",
    "ptyx_NA",
    "ptyx2_NA",
    "sheeba_SH",
    "smdmitry_AR",
    "smdmitry_EU",
    "smdmitry_SH",
    "strob_SH",
    "strobnidan_SH",
    "tokel_NA",
    "tonyl_AR",
    "tonyl_DEV",
    "van_EU",
    "webworker01_EU",
    "webworker01_NA",
    "who-biz_NA",
    "yurii-khi_DEV",
    "ca333_EU",
    "dragonhound_DEV",
];

const DPOW_SIGCHANNEL: u32 =
    b's' as u32 | (b'i' as u32) << 8 | (b'g' as u32) << 16 | (b's' as u32) << 24;
const DPOW_SIGBTCCHANNEL: u32 = !DPOW_SIGCHANNEL;
const DPOW_TXIDCHANNEL: u32 =
    b't' as u32 | (b'x' as u32) << 8 | (b'i' as u32) << 16 | (b'd' as u32) << 24;
const DPOW_BTCTXIDCHANNEL: u32 = !DPOW_TXIDCHANNEL;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
struct IguanaPacketHeader {
    sigr: [u8; 32],
    sigs: [u8; 32],
    packethash: [u8; 32],
    nonce: u32,
    packetlen: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
struct DpowNanoUtxo {
    srcutxo: [u8; 32],
    destutxo: [u8; 32],
    bestmask: [u8; 8],
    recvmask: [u8; 8],
    pendingcrc1: u32,
    pendingcrc2: u32,
    paxwdcrc: u32,
    srcvout: u16,
    destvout: u16,
    #[serde(with = "BigArray")]
    sig1: [u8; 128],
    #[serde(with = "BigArray")]
    sig2: [u8; 128],
    siglens: [u8; 2],
    pad: u8,
    bestk: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
struct DpowNanoMsgHdr {
    srchash: [u8; 32],
    desthash: [u8; 32],
    //ratify: DpowNanoUtxo,
    notarize: DpowNanoUtxo,
    channel: u32,
    height: u32,
    size: u32,
    datalen: u32,
    crc32: u32,
    myipbits: [u8; 4],
    numipbits: u32,
    #[serde(with = "BigArray")]
    ipbits: [[u8; 4]; 128],
    symbol: [u8; 16],
    senderind: u8,
    senderind2: u8,
    version1: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
struct dpow_txid_tx {
    txid: [u8;32],
    tx: Transaction
}

fn print_hex(bytes: &[u8]) {
    for b in bytes {
        print!("{:02X}", b);
    }
    println!("");
}

fn init_db(conn: &Connection) {
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
}

fn init_notaries_table(conn: &Connection, identities: [&str; 64]) {
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
fn init_ip_bits_dump_table(conn: &Connection) {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ipbits ( 
        id INTEGER PRIMARY KEY,
        ip TEXT NOT NULL UNIQUE
        )",
        params![]).unwrap();

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
        params![]).unwrap();
}

#[test]
fn test_init_db() {
    let path = "./test.db";
    let conn = Connection::open(path).unwrap();
    init_db(&conn);
    init_notaries_table(&conn, FIRST_PARTY);
    update_lastseen(&conn, 63);
    update_ip_logs(&conn, 63, "1.1.1.1".to_string());
    update_ip_logs(&conn, 63, "1.2.3.4".to_string());
    init_ip_bits_dump_table(&conn);

    update_known_ips(&conn, 63, [[188, 34, 187, 0], [178, 159, 2, 2], [91, 193, 181, 3], [178, 159, 2, 4], [51, 161, 134, 5], [178, 159, 2, 6], [139, 99, 148, 6], [139, 45, 251, 6], [46, 17, 99, 12], [80, 209, 242, 17], [139, 99, 208, 23], [139, 99, 148, 25], [178, 63, 67, 29], [198, 244, 200, 30], [149, 56, 30, 31], [103, 195, 100, 32], [198, 244, 254, 34], [144, 48, 38, 37], [139, 99, 69, 38], [15, 204, 143, 38], [77, 244, 75, 39], [15, 235, 64, 45], [198, 244, 179, 45], [149, 56, 28, 54], [54, 39, 107, 58], [65, 108, 238, 59], [158, 69, 53, 61], [139, 99, 124, 63], [139, 99, 145, 64], [139, 99, 69, 66], [139, 99, 209, 76], [177, 54, 149, 80], [115, 140, 250, 82], [82, 202, 230, 86], [82, 202, 230, 87], [148, 170, 214, 94], [185, 175, 46, 101], [148, 251, 131, 101], [51, 195, 189, 104], [49, 12, 83, 114], [139, 99, 145, 114], [77, 74, 197, 115], [177, 54, 144, 116], [88, 99, 193, 119], [51, 161, 196, 120], [158, 69, 18, 121], [51, 161, 196, 124], [149, 56, 17, 127], [139, 99, 145, 129], [116, 124, 50, 130], [37, 19, 200, 133], [77, 75, 121, 138], [88, 99, 150, 139], [77, 75, 121, 140], [31, 184, 215, 140], [51, 210, 217, 144], [37, 19, 200, 149], [157, 90, 84, 154], [188, 143, 140, 154], [136, 243, 60, 155], [114, 203, 1, 156], [95, 217, 196, 157], [146, 70, 211, 158], [135, 148, 122, 159], [135, 148, 122, 160], [167, 235, 1, 164], [142, 44, 143, 165], [95, 163, 90, 170], [139, 99, 209, 170], [95, 163, 90, 172], [136, 243, 19, 173], [95, 163, 90, 174], [180, 149, 230, 175], [91, 206, 15, 176], [51, 161, 196, 176], [66, 248, 204, 186], [51, 161, 87, 187], [51, 195, 148, 187], [188, 134, 74, 188], [95, 216, 39, 190], [51, 161, 198, 195], [2, 56, 154, 200], [139, 99, 239, 201], [51, 161, 196, 203], [172, 93, 101, 204], [167, 235, 63, 205], [84, 38, 189, 208], [158, 69, 118, 215], [148, 113, 1, 226], [78, 46, 23, 228], [65, 21, 33, 231], [185, 192, 124, 235], [38, 91, 101, 236], [162, 55, 89, 237], [209, 222, 101, 247], [82, 202, 230, 247], [167, 114, 197, 249], [51, 161, 205, 249], [82, 202, 230, 249], [82, 202, 230, 251], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]].to_vec());
}

fn now_sec() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn update_ip_logs(conn: &Connection, notary_id: u8, ip_str: String) {
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

fn update_known_ips(conn: &Connection, notary_id: u8, ips: Vec<[u8; 4]>) {
    let current_timestamp = now_sec();

    for ip in ips {
        if ip == [0;4] {
            continue;
        }
        let ip_str = Ipv4Addr::from(u32::from_be_bytes(ip)).to_string();

        // Insert the IP address into the ips table if it doesn't exist already
        conn.execute(
            "INSERT OR IGNORE INTO ipbits (ip) VALUES (?)",
            params![ip_str],
        ).unwrap();

        // Get the id of the ip address in the ips table
        let ip_id: i64 = conn.query_row(
            "SELECT id FROM ipbits WHERE ip = ?",
            params![ip_str],
            |row| row.get(0),
        ).unwrap();

        // Check if this notary/IP combination exists in the notary_ips table
        let mut stmt = conn.prepare("SELECT * FROM notary_ipbits WHERE notary_id = ? AND ip_id = ?").unwrap();
        let rows = stmt.query_map(params![notary_id, ip_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        }).unwrap();

        if rows.count() > 0 {
            // If the notary/IP combination exists, update the last_seen field
            conn.execute(
                "UPDATE notary_ipbits SET last_seen = ? WHERE notary_id = ? AND ip_id = ?",
                params![current_timestamp, notary_id, ip_id],
            ).unwrap();
        } else {
            // If this is a new notary/IP combination, insert a new row with current timestamp as both first_seen and last_seen
            conn.execute(
                "INSERT INTO notary_ipbits (notary_id, ip_id, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                params![notary_id, ip_id, current_timestamp, current_timestamp],
            ).unwrap();
        }
    }
}


fn update_lastseen(conn: &Connection, notary_id: u8) {
    conn.execute(
        "UPDATE notaries SET lastseen = ? WHERE id = ?",
        params![now_sec(), notary_id],
    )
    .unwrap();
}

fn verify_packethash(header: &IguanaPacketHeader, buffer: &Vec<u8>) -> Result<(),()> {
    let mut preimage: Vec<u8> = Vec::new();
    preimage.write_u32::<LittleEndian>(header.nonce).unwrap();
    preimage.write_u32::<LittleEndian>(header.packetlen).unwrap();
    preimage.extend(buffer);

    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let binding = hasher.finalize();
    let result = binding.as_slice();

    if result == header.packethash {
        Ok(())
    } else { 
        Err(())
    }
}

//https://stackoverflow.com/questions/68583968/how-to-deserialize-a-c-struct-into-a-rust-struct
fn main() {
    let conn = Connection::open("./stats.db").unwrap();
    init_db(&conn);
    init_notaries_table(&conn, FIRST_PARTY);
    init_ip_bits_dump_table(&conn);

    let args: Vec<String> = env::args().collect();
    let server_url = &args[1];

    let binconf = bincode::DefaultOptions::new().with_fixint_encoding(); //.allow_trailing_bytes();

    let mut in_socket = Socket::new(Protocol::Bus).expect("cannot create socket");
    let _in_endpoint = in_socket.bind(server_url).expect("cannot bind to socket");

    let mut buffer = vec![];
    loop {
        match in_socket.read_to_end(&mut buffer) {
            Ok(_mysize) => {
                loop {
                    if buffer.len() == 0 {
                        break;
                    };


                    let header: IguanaPacketHeader = binconf.deserialize(&buffer[..104]).unwrap();
                    buffer = buffer[104..].to_vec();

                    verify_packethash(&header, &buffer).unwrap();

                    let msg_size = std::mem::size_of::<DpowNanoMsgHdr>() - 1;
                    let dpow_msg: DpowNanoMsgHdr =
                        binconf.deserialize(&buffer[..msg_size]).unwrap();
                    buffer = buffer[msg_size..].to_vec();

                    update_lastseen(&conn, dpow_msg.senderind);
                    update_ip_logs(
                        &conn,
                        dpow_msg.senderind,
                        Ipv4Addr::from(u32::from_be_bytes(dpow_msg.myipbits)).to_string(),
                    );
                    update_known_ips(&conn, dpow_msg.senderind, dpow_msg.ipbits.to_vec());

                    let extra = &buffer[..dpow_msg.datalen as usize];

                    println!(
                        "{} {}",
                        FIRST_PARTY[dpow_msg.senderind as usize],
                        Ipv4Addr::from(u32::from_be_bytes(dpow_msg.myipbits))
                    );
                    println!("dpow_msg: {:?}", dpow_msg);
                    
                    match dpow_msg.channel {
                        DPOW_SIGCHANNEL => {
                            println!("DpowSigchannel");
                            print_hex(&extra);
                            //println!("extra: {:?}", &extra);
                            //let sigentry: dpow_sigentry =
                            //    binconf.deserialize(&extra).unwrap();
                            //println!("sigentry: {:?}", sigentry);
                            },
                        DPOW_SIGBTCCHANNEL => {
                            println!("DPOW_SIGBTCCHANNEL extra:");
                            print_hex(&extra);
                            //println!("extra: {:?}", &extra);
                            //let sigentry: dpow_sigentry =
                            //    binconf.deserialize(&extra).unwrap();
                            //println!("sigentry: {:?}", sigentry);
                        },
                        DPOW_TXIDCHANNEL => {
                            println!("DPOW_TXIDCHANNEL extra:");
                            print_hex(&extra);
                            //let _txid = &extra[..32];
                            //let _tx: Transaction = deserialize(&extra[32..]).unwrap();
                            //println!("tx: {:?}", tx);
                            //println!("txid: {:?}", txid);
                        },
                        DPOW_BTCTXIDCHANNEL => {
                            println!("DPOW_BTCTXIDCHANNEL extra:");
                            print_hex(&extra);
                            //let _txid = &extra[..32];
                            //let _tx: Transaction = deserialize(&extra[32..]).unwrap();
                            //println!("tx: {:?}", tx);
                            //println!("txid: {:?}", txid);
                        },
                        _ => (),//println!("Null channel"),
                    }
                    
                    buffer = buffer[dpow_msg.datalen as usize..].to_vec();
                }
            }
            Err(err) => {
                println!("Client failed to receive msg '{}'.", err);
                break;
            }
        }
    }
}

/*
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
struct dpow_sigentry {
    beacon: [u8; 32],
    mask: [u8; 8],
    refcount: u32,
    senderind: u8,
    lastk: u8,
    siglen: u8,
    #[serde(with = "BigArray")]
    sig: [u8; 128],
    #[serde(with = "BigArray")]
    senderpub: [u8; 33],
}
*/

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
struct dpow_sigentry {
    beacon: [u8; 32],
    mask: [u8; 8],
    refcount: u32,
    senderind: u8,
    lastk: u8,
    siglen: u8,
    //#[serde(with = "BigArray")]
    //sig: [u8; 128],
    //#[serde(with = "BigArray")]
    //senderpub: [u8; 33],
}




#[test]
fn test_sigentry_deser() {
    let buffer = [63, 6, 103, 0, 152, 0, 0, 8, 14, 128, 73, 72, 48, 69, 2, 33, 0, 190, 23, 138, 104, 61, 150, 33, 253, 109, 169, 232, 6, 92, 28, 63, 168, 21, 154, 227, 179, 239, 204, 61, 155, 34, 67, 20, 157, 28, 207, 58, 117, 2, 32, 6, 89, 184, 201, 89, 254, 214, 10, 147, 195, 188, 231, 189, 75, 58, 70, 224, 78, 143, 234, 47, 49, 121, 192, 145, 202, 38, 73, 255, 142, 11, 138, 1, 144, 217, 82, 20, 119, 17, 95, 195, 62, 151, 35, 232, 33, 196, 166, 150, 210, 105, 21, 149, 128, 155, 124, 21, 50, 53, 122, 45, 41, 114, 190, 197, 3, 142, 1, 12, 51, 197, 107, 97, 56, 148, 9, 238, 165, 89, 127, 225, 121, 103, 57, 135, 49, 226, 49, 133, 200, 76, 71, 42, 22, 252, 93, 52, 171];

    let binconf = bincode::DefaultOptions::new().with_fixint_encoding().allow_trailing_bytes();
    println!("{}", buffer.len());
    let sigentry: dpow_sigentry = binconf.deserialize(&buffer).unwrap();
    println!("sizeof: {}", std::mem::size_of::<DpowNanoMsgHdr>());
    println!("sigentry: {:?}", sigentry);
}

#[test]
fn test_txidtx_deser() {
    use bincode::Options;
    use rustc_hex::FromHex;
    use serialization::deserialize;

    let _binconf = bincode::DefaultOptions::new().with_fixint_encoding(); //.allow_trailing_bytes();
    let buf_hex = "A9BF9F58C6CD6ACB84AA76A55E6CA37A400C576FC2ECBAFFD37F714F857A2C6F0400008085202F890DAC3E26D98A02B317E9D9C6F1AFD5DB058C1564E60B4C9D86FE54C893CEE3DF0A010000004847304402201420E976225939CCD21FA908F58A049CFDE3C3BAD9AE8A27EB6D8A793769298502203DF3FC8A6891A08A48FDDC0C883E3AC261AAA96A4842A51AC7FDD073FB70136801FFFFFFFFBC9A413EC2F1A9DB03F73A4AE26E2C161B556617ACC1D294E30DBE6BCD135AA10C00000049483045022100BE9FE9D7C710E552824A6490CE1926B72AF68A361DC2B9DA905D36BFB952526E02200DC5BF7BE902253033CCAE99634022536A77B29D1B2A1C36E1AE7E8FE4A3008F01FFFFFFFFCBDD30915029105E2356DC748CF972A612D7632E2DAEB2F4F198951AC5343A470700000048473044022030E55AFDDA700D3A290F68D1A2F6A900715490F0B1E7C0041BF9C67D71E1B480022064204F01113CF211CE7F9E8C228971DCD8486F2506802388F08477F5E8A15B6501FFFFFFFFC1AF00C54D7E19E91B06319E3920585039163579EBD1DC70A5A5C89B2F2BF59E0300000048473044022007D9A302B554FE0455896B1ED099AE31ED0A548BB69B0985763A77A129A4B15702205DAACA04667C27EB061633EDB69A004201295B8926288764BB144F538EE450E001FFFFFFFF6813F0D6A65D796F83763C64DDAADB0D3B5BFC38EEF66A686D50492F310E0C0306000000484730440220360D8DB78BC43CDF1646A6AD251FC10BCE2FA34300BB97826F1EA404919ACA8102201044F86A3060A6313119574D213C256087445244C724D1AAEEE4847A456E747B01FFFFFFFF1D79486A2DB184FC89FDCE51E0331150D3348242AC476CFB6F43B9CF962FC6000000000049483045022100927875E194339D179D4A7748E428E98EE1E212B7F300A110C86F6FAF88E661CC022059AFFD55A3186CA9E8393140DB5C3B4049E30419BD80854C38E6DAE9D42C6B8101FFFFFFFFAF94EE21D30E77A3657D98DF38CACC161D301CA28A711623361E0881E4E8DCD71200000048473044022017CA2331224EDB375CF7590A4F1D6D40766DEE76CD32526C9273B52E7F9884EA022045A0C40A187FE09AF06E9A9BAA174DD1DA51A60B040A7DD844C06A5219BDD50201FFFFFFFF9E09D31FB58F73F2D4C4A6A65A2EF2B74D00D9104C378D08B23EBE9CBFC5478A2100000049483045022100B9F2CC0E06C3A6E8A80B46EE3D535EEECA5EFF078A328AED8897E6D10BB39D770220411C7ADB6C162C112BFA9E02193DA3455D0F2BC4B0B343F7AC0349E3904271FF01FFFFFFFF4F1CF238BBE4F9C588BCC69AFB20825CD51C491F067AC239D18B1014887AC4001A00000049483045022100EA96C0E1EC9A9DB5CEC81FFF6BCB792C5907B6CA3FDF7AF3E0D8889B59B36E84022014DEA4B4D1DA5F9E436AA49D1E5C8C570294DA344F9F971DC7CC899FEDDBCBF701FFFFFFFF4125D7D74C021136422E487AD432237BF2484662C8EE2CCB041F08CFF2BB02DA1700000049483045022100E47B9ADA633A436E021337FD33ECD066D172976FBAA4D5B3C5B32B04C720FEAB02205A4C58C10221C1657DE9EE324D4A8D9A2808D48A5D8E9D2AE5EC05281977C90E01FFFFFFFF14483E6EA88C528F438E97955D3437E73A3D24706D307D07AF2E02454892B6950E000000494830450221009F9D99BAABD5255ABB90B95D341C556D6A2799339FD932C2505617D47A8A196602201878DB3CFF1C31AEC7E6AB5D80041558AAD93053DECFFBFC029A65A54A3C8EE101FFFFFFFFAAEEFA79797DBE8F7310CEB9CBD142247536CCF3B0CBA542142A027838B589B115000000494830450221008A4ED798B4801793BD588DE16CD8A06DCD20E8281AC2B2F69493E3D1EA06D1B202202F7C92C7BBE5C924F4BFAEA401B6803C43A777F957BEE39BD567A32BB65D2B9201FFFFFFFF1B5EA0918FBE8B76B7021AF29D77895C2C9CFE48383D8F7B7C42318AF55FE9C7320000004847304402207B04FC8094FC39D08F0139E8454DA7007C63C54D432F82B1BDDCBBAA55FF90E102201D2A938321BA91F9BC9396F07D4B4DA71C80F4133CAF16EF5052CC2FDD11879301FFFFFFFF02F0810100000000002321020E46E79A2A8D12B9B5D12C7A91ADB4E454EDFAE43C0A0CB805427D2AC7613FD9AC00000000000000004F6A4C4C595AB3A541645D21AEF8C638AF8ECB956CC09462632B3B06E71CD5C3CCB65001B61924004D475700047D1B7838EF61A29B4073BFE4F8FF6717559F300821B90D91EAAE926A1C0DBE2C00000000000000000000000000000000000000000000".to_string();

    let buffer = buf_hex.from_hex::<Vec<u8>>().unwrap();

    let tx: Transaction = deserialize(&buffer[32..] as &[u8]).unwrap();

    println!("s {:?}", tx);
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct TxidTx {
    txid: [u8; 32],
    tx: Transaction,
}

#[test]
fn test_bincode() {
    use bincode::Options;
    use rustc_hex::FromHex;
    let binconf = bincode::DefaultOptions::new().with_fixint_encoding(); //.allow_trailing_bytes();
    let exp_hex = "1db4bb74c4a380deb176154ca1bd16ca3412a14bee8518d771d9b26d5731257423b80b567d3df2ebda084dee07dee33f9e8f59f8ddae8ab11c154adc26d9fc2b00166718fbb7657ff2a43b7fa60477745d94c12e29273b77a0575397adb2afc91d010000370b0000b3c168ed4acd96594288cee3114c77de51b6afe1ab6a866887a13a96ee80f33c00000015003a1d53e5cc0a54f30c644108a6768e3cad134f4014da68ab8caece0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000465920e27e5092f4d9501a5179fde66c002dff5bc48f680442995353e0e25750f6f9378ab576154f0e64775d058041382e715ed7e5f5bebaf0696c74c5287a170000000000000000400000008000008000000000000000004894338d0200020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff0000000022480900370b0000000000000000000068eedd3d4e000000bc22bb005bc1b502b29f0203b29f02058b2dfb06b29f0207b29f0208334fe4082e11630c50d1f211334f6316c6f4c81633a1c417b23f431d33a1c41dc6f4c81dbcf6e01d9030262133a1c4214df44b278b637932b1369332b1369c348b6395369538113936276b3a8b63793b68eedd3d8794ab4a3351384ca237055352cae65452cae6558b63d064362785698ac9cf734d4ac574550ac275bcf6e0754d4ac5769e45127a36271c7b0feb52845fd95787879436896732218a34812c8a4d4b798b5c35418d8b63d08dc77f3c8e33a1838f36251e97bc8f8c9a87b5dfa45fd991a65fa35aa95fa35aab5fa35aad33a1c4b0023899b642f8ccbab00908bbbc864abcb996bfbf67d8dfc18b63efc9a23758e34e2e17e48b63bde4b9c07ceb8b6390f052cae6f8a772c5fa33a1cdfa52cae6fa52cae6fb52cae6fc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000544f4b454c00000000000000000000003f8217".to_string();
    let packet = exp_hex.from_hex::<Vec<u8>>().unwrap();
    let header_vec = &packet[..104];
    let header_safe: IguanaPacketHeader = binconf.deserialize(header_vec).unwrap();
    println!("header {:?}", header_safe);

    let pack_vec = &packet[104..(header_safe.packetlen + 104) as usize];

    let packet_safe: DpowNanoMsgHdr = binconf.deserialize(pack_vec).unwrap();
    println!("pack {:?}", packet_safe);
}


#[test]
fn test_sha_packethash() {
    use bincode::Options;
    let binconf = bincode::DefaultOptions::new().with_fixint_encoding(); //.allow_trailing_bytes();
    use sha2::{Sha256, Digest};
    use byteorder::{LittleEndian, WriteBytesExt};

    let mut packet_buffer = [146, 169, 54, 213, 196, 68, 87, 116, 230, 104, 86, 65, 192, 199, 206, 239, 233, 210, 39, 221, 125, 65, 204, 131, 161, 134, 139, 184, 57, 84, 195, 75, 20, 165, 18, 239, 7, 173, 88, 81, 209, 146, 225, 5, 39, 166, 74, 199, 156, 143, 33, 235, 235, 1, 37, 230, 69, 181, 19, 184, 155, 26, 221, 237, 0, 225, 154, 14, 237, 118, 5, 149, 145, 44, 234, 24, 130, 10, 44, 133, 193, 210, 4, 15, 195, 13, 106, 11, 13, 129, 82, 74, 126, 31, 183, 243, 1, 1, 0, 0, 55, 5, 0, 0, 54, 244, 104, 72, 218, 174, 175, 177, 227, 86, 40, 196, 76, 61, 247, 244, 159, 164, 111, 41, 13, 229, 101, 208, 153, 52, 120, 225, 158, 25, 8, 93, 0, 95, 50, 92, 119, 2, 189, 148, 211, 109, 113, 8, 169, 181, 194, 50, 35, 28, 242, 223, 29, 201, 213, 207, 61, 108, 151, 35, 134, 25, 191, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 9, 120, 239, 200, 105, 190, 202, 16, 113, 16, 246, 170, 177, 19, 35, 170, 116, 24, 131, 38, 108, 10, 167, 219, 59, 94, 49, 195, 175, 8, 129, 69, 39, 68, 75, 40, 37, 134, 170, 19, 154, 115, 17, 22, 167, 209, 104, 70, 227, 6, 250, 169, 12, 35, 241, 166, 119, 78, 197, 9, 149, 85, 60, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 72, 154, 52, 255, 29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 72, 125, 1, 0, 55, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 195, 201, 137, 5, 1, 0, 0, 0, 195, 201, 137, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 77, 65, 82, 84, 89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 130, 23].to_vec();

    let header: IguanaPacketHeader = binconf.deserialize(&packet_buffer[..104]).unwrap();
    println!("HEADER {:?}",header);

    packet_buffer = packet_buffer[104..].to_vec();


    let mut preimage: Vec<u8> = Vec::new();
    preimage.write_u32::<LittleEndian>(header.nonce).unwrap();
    preimage.write_u32::<LittleEndian>(header.packetlen).unwrap();
    preimage.extend(packet_buffer);

    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let binding = hasher.finalize();
    let result = binding.as_slice();

    assert_eq!(result, header.packethash);
}
