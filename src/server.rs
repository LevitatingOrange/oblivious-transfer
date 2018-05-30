#[macro_use]
extern crate structopt;
extern crate ot;
extern crate rand;
extern crate tungstenite;

use ot::common::digest::sha3::SHA3_256;
use ot::sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::sync::base_ot::{BaseOTReceiver, BaseOTSender};
use ot::sync::crypto::aes::AesCryptoProvider;
use rand::{ChaChaRng, FromEntropy};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
use structopt::StructOpt;
use tungstenite::handshake::server::Request;
use tungstenite::server::accept_hdr;
use tungstenite::Message;

use std::time::Instant;

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
                    let rng = ChaChaRng::from_entropy();
                    if message == "receive".as_bytes() {
                        println!("Receiving values...");
                        let now = Instant::now();
                        let mut receiver = ChouOrlandiOTReceiver::new(
                            stream,
                            SHA3_256::default(),
                            AesCryptoProvider::default(),
                            rng,
                        ).unwrap();
                        let lock = args.lock().unwrap();
                        let result = receiver.receive(lock.index, lock.length).unwrap();
                        println!(
                            "Got values: {} in {:?}",
                            String::from_utf8(result).unwrap(),
                            now.elapsed()
                        );
                        // TODO: make this more idiomatic
                        stream = receiver.conn;
                    } else if message == "send".as_bytes() {
                        println!("Sending values...");
                        let now = Instant::now();
                        let mut sender = ChouOrlandiOTSender::new(
                            stream,
                            SHA3_256::default(),
                            AesCryptoProvider::default(),
                            rng
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
                        println!("sent values in {:?}!", now.elapsed());
                        stream = sender.conn;
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
