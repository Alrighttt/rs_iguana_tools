use bincode::Options;
use nanomsg::{Protocol, Socket};

use std::env;
use std::io::Read;
use std::thread;

use iguana_rs::{
    validate_packet_signature, validate_packethash, DpowNanoMsgHdr, IguanaPacketHeader, FIRST_PARTY,
};

// TODO: cleanup all db OPs into other file
use iguana_rs::db::{init_db, update_ip_logs, update_known_ips, update_lastseen};
use rusqlite::Connection;

use jsonrpc_core::types::error::Error;
use jsonrpc_core::types::params::Params;
use jsonrpc_core::types::Value;
use jsonrpc_core::IoHandler;
use jsonrpc_http_server::ServerBuilder;
//use jsonrpc_http_server::*;
use std::sync::{Arc, Mutex};

use futures::future;

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

fn printinfo(dpow_msg: &DpowNanoMsgHdr) {
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
}

fn connect_to_ip(socket: &mut Socket, ip: &String, port: &String ) {
    let dial = format!("tcp://{}:{}", ip, port);
    let _out_endpoint = match socket.connect(&dial) {
        Ok(_) => {
            println!("connect to {}", dial);
        }
        Err(_) => println!("failed connect to {}", dial),
    };
}

fn connect_to_known_ips(conn: &Connection, socket: &mut Socket, server_port: &String) {
    let mut stmt = conn.prepare("SELECT ip FROM ipbits").unwrap();

    let rows = stmt.query_map([], |row| {
        let ip: String = row.get(0)?;
        Ok(ip)
    }).unwrap();

    for ip_result in rows {
        if let Ok(ip) = ip_result {
            connect_to_ip(socket, &ip, server_port);
        }
    }
}

// usage ./iguana_rs_listener <external IP to bind to> <port to bind to> <initial peer to connect to> <db filename>
fn main() {
    let args: Vec<String> = env::args().collect();

    let server_ip = args[1].clone();
    let server_port = args[2].clone();
    let server_url = format!("tcp://{}:{}", server_ip, server_port);

    let bootstrap_peer = args[3].clone();
    let peer_string = format!("tcp://{}:{}", bootstrap_peer, server_port);

    let db_file = args[4].clone();

    let binconf = bincode::DefaultOptions::new().with_fixint_encoding();

    let mut in_socket = Socket::new(Protocol::Bus).expect("cannot create socket");
    let _in_endpoint = in_socket.bind(&server_url).expect("cannot bind to socket");

    let _out_endpoint = match in_socket.connect(&peer_string) {
        Ok(ep) => ep,
        Err(err) => panic!("Failed to connect socket: {}", err),
    };

    let mut buffer = vec![];
    //let mut connect_once = true;
    let connect_once = Arc::new(Mutex::new(true));
    let _connect_once_for_thread = connect_once.clone();

    //let mut out_sockets : Vec<Socket> = Vec::new();
    thread::spawn(move || {
        let conn = Connection::open(db_file).unwrap();
        init_db(&conn);
        connect_to_known_ips(&conn, &mut in_socket, &server_port);

        loop {
            match in_socket.read_to_end(&mut buffer) {
                Ok(_mysize) => {
                    loop {
                        if buffer.len() == 0 {
                            break;
                        };

                        let header: IguanaPacketHeader =
                            binconf.deserialize(&buffer[..104]).unwrap();
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
                        let new_ips = update_known_ips(&conn, dpow_msg.senderind, dpow_msg.ipbits.to_vec());
                        for ip in new_ips.iter() {
                            connect_to_ip(&mut in_socket, ip, &server_port);
                        }
                        printinfo(&dpow_msg);

                        let _extra = &buffer[..dpow_msg.datalen as usize];

                        buffer = buffer[dpow_msg.datalen as usize..].to_vec();
                    }
                }
                Err(err) => {
                    println!("Client failed to receive msg '{}'.", err);
                    break;
                }
            }
        }
    });

    thread::spawn(move || {
        let mut io = IoHandler::default();
        let connect_once_rpc = connect_once.clone(); // We clone here because the closure requires ownership
        io.add_method("set_connect_once", move |params: Params| {
            future::ready(match params {
                Params::Map(map) => {
                    if let Some(Value::Bool(val)) = map.get("value") {
                        *connect_once_rpc.lock().unwrap() = *val;
                        Ok(Value::Bool(true))
                    } else {
                        Err(Error::invalid_params("Missing 'value'"))
                    }
                }
                _ => Err(Error::invalid_params("Expected map")),
            })
        });

        let server = ServerBuilder::new(io)
            .threads(3)
            .start_http(&"127.0.0.1:3030".parse().unwrap())
            .unwrap();

        println!("JSON-RPC server listening on 127.0.0.1:3030");
        server.wait();
    });

    loop {}
}
