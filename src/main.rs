use bincode::Options;
use chain::Transaction;
use nanomsg::{Protocol, Socket};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::Read;
use std::net::Ipv4Addr;

use rusqlite::{params, Connection, Result};
use std::env;

use std::time::{SystemTime, UNIX_EPOCH};

//const SERVER_DEVICE_URL: &'static str = "tcp://195.201.20.230:13344";
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
    ratify: DpowNanoUtxo,
    notarize: DpowNanoUtxo,
    channel: u32,
    height: u32,
    size: u32,
    datalen: u32,
    crc32: u32,
    myipbits: [u8; 4],
    numipbits: u32,
    #[serde(with = "BigArray")]
    ipbits: [[u8; 4]; 512],
    symbol: [u8; 16],
    senderind: u8,
    senderind2: u8,
    version1: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[repr(C)]
struct dpow_sigentry {
    beacon: [u8; 32],
    mask: [u8; 8],
    refcount: i32,
    senderind: u8,
    lastk: u8,
    siglen: u8,
    #[serde(with = "BigArray")]
    sig: [u8; 128],
    #[serde(with = "BigArray")]
    senderpub: [u8; 33],
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

#[test]
fn test_init_db() {
    let path = "./test.db";
    let conn = Connection::open(path).unwrap();
    init_db(&conn);
    init_notaries_table(&conn, FIRST_PARTY);
    update_lastseen(&conn, 63);
    update_ip_logs(&conn, 63, "1.1.1.1".to_string());
    update_ip_logs(&conn, 63, "1.2.3.4".to_string());
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
    let mut stmt = conn.prepare("SELECT * FROM ip_logs WHERE notary_id = ? AND ip = ?").unwrap();
    let rows = stmt.query_map(params![notary_id, ip_str.clone()], |row| {
        Ok((
            row.get::<_, u8>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u32>(2)?,
            row.get::<_, u32>(3)?,
        ))
    }).unwrap();

    if rows.count() > 0 {
        // If the server has used this IP before, update the last_seen field
        conn.execute(
            "UPDATE ip_logs SET last_seen = ? WHERE notary_id = ? AND ip = ?",
            params![now, notary_id, ip_str],
        ).unwrap();
    } else {
        // If this is a new IP for the server, insert a new row
        conn.execute(
            "INSERT INTO ip_logs (notary_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            params![notary_id, ip_str, now, now],
        ).unwrap();
    }
}

fn update_lastseen(conn: &Connection, notary_id: u8) {
    conn.execute(
        "UPDATE notaries SET lastseen = ? WHERE id = ?",
        params![now_sec(), notary_id],
    )
    .unwrap();
}

//https://stackoverflow.com/questions/68583968/how-to-deserialize-a-c-struct-into-a-rust-struct
fn main() {
    let conn = Connection::open("./stats.db").unwrap();
    init_db(&conn);
    init_notaries_table(&conn, FIRST_PARTY);

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

                    let _header: IguanaPacketHeader = binconf.deserialize(&buffer[..104]).unwrap();
                    buffer = buffer[104..].to_vec();
                    let msg_size = std::mem::size_of::<DpowNanoMsgHdr>() - 1;
                    let dpow_msg: DpowNanoMsgHdr =
                        binconf.deserialize(&buffer[..msg_size]).unwrap();

                    buffer = buffer[msg_size..].to_vec();

                    update_lastseen(&conn, dpow_msg.senderind);
                    update_ip_logs(&conn, dpow_msg.senderind, Ipv4Addr::from(u32::from_be_bytes(dpow_msg.myipbits)).to_string());

                    let extra = &buffer[..dpow_msg.datalen as usize];

                    /*
                    println!(
                        "{} {}",
                        FIRST_PARTY[dpow_msg.senderind as usize],
                        Ipv4Addr::from(u32::from_be_bytes(dpow_msg.myipbits))
                    );
                    println!("dpow_msg: {:?}", dpow_msg);

                    match dpow_msg.channel {
                        DPOW_SIGCHANNEL => println!("DpowSigchannel"),
                        DPOW_SIGBTCCHANNEL => println!("DpowSigbtcchannel"),
                        DPOW_TXIDCHANNEL => println!("DpowTxidchannel"),
                        DPOW_BTCTXIDCHANNEL => println!("DpowBtctxidchannel"),
                        _ => println!("Null channel"),
                    }
                    */
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

#[test]
fn test_txidtx_deser() {
    use bincode::Options;
    use rustc_hex::FromHex;
    use serialization::deserialize;

    let _binconf = bincode::DefaultOptions::new().with_fixint_encoding(); //.allow_trailing_bytes();
    let buf_hex = "66492443d13439116c9f5b979633c6f3828b59e99e896d63278167562eecdd8b0400008085202f890d8e18650989c179eade65886b5a31825f9f16ad86782cad0c8e29b81f36e1ef8d080000004847304402203c6510685dd20aaff6dad73b183c8c5ea17ffb45e616192c44010cb11264093e02205887a5d31701745c1e56b5c8f454f2c44528c3bf3a1d3c140c7c77caf5b0e58601ffffffffec8afd071dec091eba337d1bc6342a1fa3a0682df28bf62c53c58053efeb5de80300000049483045022100931f267031c20d8e6a9429ce188669ffc2277aa2ad7e5e93193c029163434a050220709fc79b03a8699604d63b64286107e3f66d04ce724690d19845ccd6570c597501ffffffffcdd03e67f187bed57b483b338776c19f496b7443e92de74b65d4a3f5a7b6f4d70b0000004847304402200bd89d1e0324c25706ab03f97feeecba6b3399ae639e341b41c95c87586fa38b02201059e853dbcb050af3502ed75b60ed14898ec3bca1cc4d5369cf1d4d4a7da82601ffffffff0e314a18230ddcce9412cde387634c184f6bbcaf54361804dfcb04b331aa84d90100000049483045022100e55fe94c82917ab8111b3c38a0dfdd5c849ec58d03c8e940605031908b8d992002201f26cadd15beea6866fb5e9ee19ddbc1f7d381a8a01437ec237fb0bf5763549b01ffffffff166b4331c7a8e2a987b86ce40cfd61d809e87a1a4eed145b27609ab5d462203f0800000049483045022100ce91b2bbefc63cdac0b6fc1c513a8836d38e196e0d2eb905af9385a813832fe50220538bb27df326a07b63bd07102dc9de73df1d5ceeeb0b517ddcbb8222487e30fc01ffffffff1fcd15c7f58c25933aa6636c37d1c9828a6f70ea4e826538894f39d1003eb01d09000000494830450221009cf59562d5b87883fa06b955b808339f5bc9757ef8431582b63984e659e1bb2302206b36fd6927322a879ed0d026c98afe204090e2f6a3c01cabbca4ebfdf6724db001ffffffffdf9a1062be5a4c46faaefe1fef5a44fd1a54db7ee6193c92b1fec24787291cd9090000004847304402202df5f1ee62418023cfd940e6c178512b5916d85abe2adf6eb4353fdf84d1032e022071d89485fc0baa26c5aadaf1631352c01ef6244e47e95a819dfd0dbc5b6c02c801ffffffff93d3377bd1dbc685d16c3924f503027da3b29a17896b04f7124379138c43abfb1400000049483045022100d971090696d348b387f3b3780930fd95dc6c7dd4d401938dedeaec17bde9861d022009f5a41ba4c2cfe84b4c1de7f18bc6a67b66e6d54c20b41db3e7c29b0121db6801ffffffff1b94ee3056c5509044920f7e9bc4044dc6ffafb5cf6a8a90fc17b49fd6ed27ae0600000049483045022100e9d5ebb77aa562d203b4bee1893828c29156242a4b7b6ebbdb1041440e0f62fc02201c349c16e16cfc4765b6cee98eca164b989f0db5b655c91fa0ce6aca1b24741601ffffffff351227440693a7a9517fc723034f0730c32746f3c0a4f41912faf79eb46233cf0200000049483045022100e85a79c6d5fa7c1bb1c39273432a52032c5a0ad86406acddbfd55a745c5e817f0220388920802d97ab12259a75093601e57378eff7b21b8c0f5d57a6abdc69df798e01fffffffffc8f798d710dad056eee6430de71126eba8c1cf9f45d0acd3c7a0b49e5654ac00500000049483045022100becde9f60fa86e009c0a0d5b0b8057a35ef044fb48be3ed841d7f40b693c0e92022023aff30c56058c5dd6beff8e5f2427ad3aca60805cf6bb5a47e241e66bd967b501ffffffff6c5a77df718e461b2c59f954a081f769ee48f2366998b830af7e07ebaa2d264b0100000049483045022100e3b9da2554e0f0697cb2dfb919cfbfccbfb6f3c10e160be29108485bb3c2fc1c02207a80d6fb47ae2a143899c439bff4e59ace4858720f46c1a109fd7d62b191778001ffffffff8e3a6cf08e172a80ae61aa1cca201fc8b318a9589f494d9411dbec9fa3d529700a00000049483045022100fe27dc5af79c97d5a685b9f3420b1b2edbf322e38585f3bd4944f0fe333892a502207da298f5e682ba8afbef3c44463a11edfe0ef3a2f45ff7d1e058c3ed8e12094001ffffffff02f0810100000000002321020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9ac00000000000000002c6a2abc2c099591c82c7a595d084b0ab2ee57f488392b20fe642f6abe5a970000000056b60a0053465553440000000000000000000000000000000000000000".to_string();

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
