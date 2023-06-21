use bincode::Options;
use chain::Transaction;
use nanomsg::{Protocol, Socket};
use serialization::deserialize;

use std::env;
use std::io::Read;

use iguana_rs::{
    validate_packet_signature, validate_packethash, DpowNanoMsgHdr, IguanaPacketHeader, FIRST_PARTY,
};

// TODO: cleanup all db OPs into other file
use iguana_rs::db::{
    init_db, update_ip_logs, update_known_ips,
    update_lastseen,
};
use rusqlite::Connection;

fn print_hex(bytes: &[u8]) {
    for b in bytes {
        print!("{:02x}", b);
    }
    println!("");
}

fn main() {
    let conn = Connection::open("./stats.db").unwrap();
    init_db(&conn);

    let args: Vec<String> = env::args().collect();
    let server_url = &args[1];

    let binconf = bincode::DefaultOptions::new().with_fixint_encoding();

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

                    validate_packethash(&header, &buffer).unwrap();
                    let _pubkey = validate_packet_signature(&header).unwrap();
                    // TODO: add "validate_pubkey" flag

                    let msg_size = std::mem::size_of::<DpowNanoMsgHdr>() - 1;
                    let dpow_msg: DpowNanoMsgHdr =
                        binconf.deserialize(&buffer[..msg_size]).unwrap();
                    buffer = buffer[msg_size..].to_vec();

                    update_lastseen(&conn, dpow_msg.senderind);
                    update_ip_logs(&conn, dpow_msg.senderind, dpow_msg.myipbits);
                    update_known_ips(&conn, dpow_msg.senderind, dpow_msg.ipbits.to_vec());

                    let extra = &buffer[..dpow_msg.datalen as usize];

                    println!(
                        "{} {:?}",
                        FIRST_PARTY[dpow_msg.senderind as usize], dpow_msg.myipbits
                    );
                    println!("dpow_msg: {:?}", dpow_msg);

                    match dpow_msg.channel {
                        iguana_rs::DPOW_SIGCHANNEL | iguana_rs::DPOW_SIGBTCCHANNEL => {
                            // this seems to be an entirely deprecated and unused data structure
                            // that is transmitted after a notarization tx is broadcast
                            // see dpow_rwsigentry() in dpow_network.c
                            ()
                        }
                        iguana_rs::DPOW_TXIDCHANNEL => {
                            println!("DPOW_TXIDCHANNEL extra:");
                            print_hex(&extra);
                            let txid = &extra[..32];
                            let tx: Transaction = deserialize(&extra[32..]).unwrap();
                            println!("tx: {:?}", tx);
                            print_hex(&txid);
                            println!("^txid");
                        }
                        iguana_rs::DPOW_BTCTXIDCHANNEL => {
                            println!("DPOW_BTCTXIDCHANNEL extra:");
                            print_hex(&extra);
                            let txid = &extra[..32];
                            let tx: Transaction = deserialize(&extra[32..]).unwrap();
                            println!("tx: {:?}", tx);
                            print_hex(&txid);
                            println!("^txid");
                        }
                        _ => (), //println!("Null channel"),
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
