#[macro_use]
extern crate structopt;
extern crate ot;
extern crate rand;
extern crate sha3;
extern crate tungstenite;

use ot::base_ot::sync::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::base_ot::sync::{BaseOTReceiver, BaseOTSender};
use ot::crypto::dummy::DummyCryptoProvider;
use rand::OsRng;
use sha3::Sha3_256;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use structopt::StructOpt;
use tungstenite::handshake::server::Request;
use tungstenite::server::accept_hdr;
use tungstenite::Message;

#[derive(StructOpt, Debug)]
#[structopt(name = "ot")]
struct Opt {
    #[structopt(name = "address", help = "Address the server should listen on")]
    address: String,
    #[structopt(name = "index", help = "Index of received value")]
    index: usize,
    #[structopt(name = "length", help = "Length of received values")]
    length: usize,
    #[structopt(name = "values", help = "Values to be transmitted")]
    values: Vec<String>,
}

fn main() {
    let args = Arc::new(Mutex::new(Opt::from_args()));
    let server = TcpListener::bind(&args.lock().unwrap().address).unwrap();
    for stream in server.incoming() {
        let args = args.clone();
        let callback = |req: &Request| {
            println!("Received a new ws handshake");
            println!("The request's path is: {}", req.path);
            println!("The request's headers are:");
            for &(ref header, _ /* value */) in req.headers.iter() {
                println!("* {}", header);
            }

            // TODO: for better example decide based on the subprotocol if you send or receive
            let extra_headers = vec![(String::from("Sec-WebSocket-Protocol"), String::from("ot"))];
            Ok(Some(extra_headers))
        };
        spawn(move || {
            let mut stream = accept_hdr(stream.unwrap(), callback).unwrap();
            loop {
                if let Ok(Message::Binary(message)) = stream.read_message() {
                    if message == "receive".as_bytes() {
                        println!("Receiving values...");
                        let mut receiver = ChouOrlandiOTReceiver::new(
                            stream,
                            Sha3_256::default(),
                            DummyCryptoProvider::default(),
                            OsRng::new().unwrap(),
                        ).unwrap();
                        let lock = args.lock().unwrap();
                        let result = receiver.receive(lock.index, lock.length).unwrap();
                        println!("Got values: {}", String::from_utf8(result).unwrap());
                        // TODO: make this more idiomatic
                        stream = receiver.conn;
                    } else if message == "send".as_bytes() {
                        println!("Sending values...");
                        let mut sender = ChouOrlandiOTSender::new(
                            stream,
                            Sha3_256::default(),
                            DummyCryptoProvider::default(),
                            &mut OsRng::new().unwrap(),
                        ).unwrap();
                        let vals = args.lock().unwrap().values.to_owned();
                        sender
                            .send(
                                vals.iter()
                                    .map(|s| {
                                        let bytes = s.as_bytes();
                                        bytes
                                    })
                                    .collect(),
                            )
                            .unwrap();
                        stream = sender.conn;
                        println!("sent values!");
                    } else {
                        println!("Could not understand message");
                    }
                } else {
                    println!("Socket closed!");
                    break;
                }
            }

            //println!("{:?}", sender.compute_keys(10));
        });
    }
}
