use core::panic;
use std::{net::{Ipv4Addr, SocketAddrV4, UdpSocket}, io::{Result, ErrorKind}, thread, time, sync::{atomic::{AtomicBool, Ordering}, Arc}, env};
use ctrlc;
use server_finder;

const GROUP_ADDR: Ipv4Addr = Ipv4Addr::new(230, 69, 69, 1);
const GROUP_PORT: u16 = 5454;
const TCP_PORT: u16 = 5469;
const PHRASE: &str = "TestServer";
const SECRET: &str = "b36914ad-0062-4118-aa72-fb40c0789647";

fn main() {
    let running = Arc::new(AtomicBool::new(true)); // Bool for controlling any threads.
    // Setup Ctrl+C for exiting threads.
    let run_clone = running.clone(); // Clone for move.
    ctrlc::set_handler(move || {
        println!("Ctrl+C");
        run_clone.store(false, Ordering::SeqCst);
    }).expect("Should set running to false.");
    // Get arguments from command line to launch proper mode.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("No mode specified.");
    }
    match (&args[1]).as_str() {
        "client" => client(),
        "server" => server(),
        _ => panic!("Invalid mode specified.")
    }
}

fn client() {
    println!("Running as client.");
    server_finder::find_server(
        GROUP_ADDR, GROUP_PORT, String::from(PHRASE)).expect("should find server");
}

fn server() {
    println!("Running as server.");
    server_finder::find_client(
        GROUP_ADDR, GROUP_PORT, TCP_PORT, String::from(PHRASE), String::from(SECRET)).expect("should find client");
}