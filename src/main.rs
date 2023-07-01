use bincode::Options;
use nanomsg::{Protocol, Socket};

use std::env;
use std::io::Read;

use iguana_rs::{
    validate_packet_signature, validate_packethash, DpowNanoMsgHdr, IguanaPacketHeader, FIRST_PARTY,
};

// TODO: cleanup all db OPs into other file
use iguana_rs::db::{init_db, update_ip_logs, update_known_ips, update_lastseen};
use rusqlite::Connection;

fn print_hex(bytes: &[u8]) {
    for b in bytes {
        print!("{:02x}", b);
    }
    println!("");
}
use std::net::Ipv4Addr;

fn reverse_bits(byte: u8) -> u8 {
    let mut v = byte;
    let mut r = v;
    let mut s = 7;
    v >>= 1;
    while v != 0 {
        r <<= 1;
        r |= v & 1;
        v >>= 1;
        s -= 1;
    }
    r <<= s;
    r
}

// usage ./iguana_rs_listener <external IP to bind to> <port to bind to> <initial peer to connect to> <db filename>
fn main() {
    let args: Vec<String> = env::args().collect();

    let server_ip = &args[1];
    let server_port = &args[2];
    let server_url = format!("tcp://{}:{}", server_ip, server_port);

    let bootstrap_peer = &args[3];
    let peer_string = format!("tcp://{}:{}", bootstrap_peer, server_port);

    let conn = Connection::open(&args[4]).unwrap();
    init_db(&conn);

    let binconf = bincode::DefaultOptions::new().with_fixint_encoding();

    let mut in_socket = Socket::new(Protocol::Bus).expect("cannot create socket");
    let _in_endpoint = in_socket.bind(&server_url).expect("cannot bind to socket");

    let _out_endpoint = match in_socket.connect(&peer_string) {
        Ok(ep) => ep,
        Err(err) => panic!("Failed to connect socket: {}", err),
    };

    let mut buffer = vec![];
    let mut connect_once = true;
    //let mut out_sockets : Vec<Socket> = Vec::new();
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

                    if connect_once {
                        for ip in dpow_msg.ipbits.iter() {
                            let ip_str = Ipv4Addr::from(u32::from_be_bytes(*ip)).to_string();
                            println!("ip_str {}", ip_str);
                            if ip != &[0; 4] && server_ip != &ip_str && bootstrap_peer != &ip_str {
                                let dial = format!("tcp://{}:{}", ip_str, server_port);
                                println!("dial {}", dial);
                                // TODO we want thread per connection to be able to send/receive selectively
                                //let mut out_socket = Socket::new(Protocol::Bus).expect("cannot create socket");
                                let _out_endpoint = match in_socket.connect(&dial) {
                                    Ok(_) => {
                                        println!("connect to {}", dial);
                                        //out_sockets.push(out_socket);
                                    }
                                    Err(_) => println!("failed connect to {}", dial),
                                };
                            }
                        }
                        connect_once = false;
                    }

                    let _extra = &buffer[..dpow_msg.datalen as usize];

                    println!(
                        "{} {:?} {} {} channel:{:?} bestk:{}",
                        FIRST_PARTY[dpow_msg.senderind as usize],
                        dpow_msg.myipbits,
                        std::str::from_utf8(&dpow_msg.symbol).unwrap(),
                        dpow_msg.height,
                        dpow_msg.channel,
                        dpow_msg.notarize.bestk,
                    );
                    print!("bestmask:");
                    for byte in &dpow_msg.notarize.bestmask {
                        print!("{:08b}", reverse_bits(*byte));
                    }
                    println!();
                    print!("recvmask:");
                    for byte in &dpow_msg.notarize.recvmask {
                        print!("{:08b}", reverse_bits(*byte));
                    }
                    println!();
                    print!("srchash:");
                    print_hex(&dpow_msg.srchash);
                    print!("desthash:");
                    print_hex(&dpow_msg.desthash);

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
