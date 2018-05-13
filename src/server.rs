#[macro_use]
extern crate structopt;
extern crate ot;
extern crate rand;
extern crate sha3;
extern crate tungstenite;

use ot::crypto::dummy::DummyCryptoProvider;
use ot::base_ot::sync::chou::ChouOrlandiOTSender;
use ot::base_ot::sync::BaseOTSender;
use rand::OsRng;
use sha3::Sha3_256;
use structopt::StructOpt;
use std::net::TcpListener;
use std::thread::spawn;
use std::sync::{Arc, Mutex};
use tungstenite::handshake::server::Request;
use tungstenite::server::accept_hdr;

#[derive(StructOpt, Debug)]
#[structopt(name = "ot")]
struct Opt {
    #[structopt(name = "address", help = "Address the server should listen on")]
    address: String,
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

                // Let's add an additional header to our response to the client.
                let extra_headers = vec![
                    (String::from("MyCustomHeader"), String::from(":)")),
                    (String::from("SOME_TUNGSTENITE_HEADER"), String::from("header_value")),
                ];
                Ok(Some(extra_headers))
            };
        spawn(move || {
            let mut sender = ChouOrlandiOTSender::new(accept_hdr(stream.unwrap(), callback).unwrap(), Sha3_256::default(), DummyCryptoProvider::default(), &mut OsRng::new().unwrap()).unwrap();
            sender.send(args.lock().unwrap().values.iter().map(|s| {
                let bytes = s.as_bytes();
                println!("{:?}", bytes);
                bytes
            }).collect()).unwrap();
            //println!("{:?}", sender.compute_keys(10));
        });
    }
}
