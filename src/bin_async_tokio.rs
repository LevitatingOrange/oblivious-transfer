#[macro_use]
extern crate structopt;

extern crate futures;
extern crate ot;
extern crate rand;
extern crate sha3;
extern crate tokio;

use ot::base_ot::chou_async::*;
use ot::crypto::dummy::DummyCryptoProvider;
use ot::errors::*;
use rand::OsRng;
use sha3::Sha3_256;
use structopt::StructOpt;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

#[derive(StructOpt, Debug)]
#[structopt(name = "ot")]
enum Opt {
    #[structopt(name = "server")]
    Server {
        #[structopt(name = "address", help = "Address the server should listen on")]
        address: String,
        #[structopt(name = "values", help = "Values to be transmitted")]
        values: Vec<String>,
    },
    #[structopt(name = "client")]
    Client {
        #[structopt(name = "address", help = "Address of the server")]
        address: String,
        #[structopt(name = "lengrh", help = "Number of values")]
        length: usize,
        #[structopt(name = "index", help = "Selected value")]
        index: usize,
    },
}

fn main() {
    match Opt::from_args() {
        Opt::Client {
            address,
            length,
            index,
        } => {
            let client = TcpStream::connect(&address.parse().unwrap())
                .map_err(move |e| Error::with_chain(e, "Error while trying to connect to sender"))
                .and_then(|s| {
                    ChouOrlandiOTReceiver::new(
                        s,
                        Sha3_256::default(),
                        DummyCryptoProvider::default(),
                        OsRng::new().unwrap(),
                    )
                })
                .and_then(move |r| r.receive(index, length))
                .and_then(move |result| {
                    future::result(String::from_utf8(result))
                        .map_err(move |e| Error::with_chain(e, "Error parsing string"))
                })
                .map_err(|err| eprintln!("Receiver Error: {}", err))
                .map(|result| println!("Got {}", result));
            tokio::run(client);
        }
        Opt::Server { address, values } => {
            let server = TcpListener::bind(&address.parse().unwrap())
                .unwrap()
                .incoming()
                .map_err(|err| eprintln!("Error establishing Connection {:?}", err))
                .for_each(move |socket| {
                    let vals = values.clone().into_iter().map(|e| e.into_bytes()).collect();
                    let sender = ChouOrlandiOTSender::new(
                        socket,
                        Sha3_256::default(),
                        DummyCryptoProvider::default(),
                        &mut OsRng::new().unwrap(),
                    ).and_then(move |s| s.send(vals))
                        .map_err(|err| eprintln!("Sender Error: {}", err));
                    tokio::spawn(sender)
                });
            tokio::run(server);
        }
    }
}
