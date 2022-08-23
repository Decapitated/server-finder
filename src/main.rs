use std::{net::{Ipv4Addr, TcpStream}, sync::{atomic::{AtomicBool, Ordering}, Arc}, env, io::{Read, Write, self}, thread, time};
use ctrlc;
use server_finder;

const GROUP_ADDR: Ipv4Addr = Ipv4Addr::new(230, 69, 69, 1);
const GROUP_PORT: u16 = 5454;
const PHRASE: &str = "TestServer";
const SECRET: &str = "b36914ad-0062-4118-aa72-fb40c0789647";

fn main() {
    let running= Arc::new(AtomicBool::new(true));
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
    let run_clone = running.clone();
    match (&args[1]).as_str() {
        "client" => client(run_clone),
        "server" => server(run_clone),
        _ => panic!("Invalid mode specified.")
    }
    println!("Finished.");
}

fn client(toggle: Arc<AtomicBool>) {
    println!("Running as client.");
    let result = server_finder::find_server(
        GROUP_ADDR, GROUP_PORT, String::from(PHRASE), String::from(SECRET), toggle.clone());
    let stream_option = match result {
        Ok(r) => r,
        Err(e) => {
            println!("(Client) {}", e);
            return;
        }
    };
    let stream = match stream_option {
        Some(r) => r,
        None => return
    };
    println!("Found server.");
    init_stream(toggle.clone(), stream);
}

fn server(toggle: Arc<AtomicBool>) {
    println!("Running as server.");
    let result = server_finder::find_client(
        toggle.clone(), GROUP_ADDR, GROUP_PORT, String::from(PHRASE), String::from(SECRET));
    let stream_option = match result {
        Ok(r) => r,
        Err(e) => {
            println!("(Server) {}", e);
            return;
        }
    };
    let stream = match stream_option {
        Some(r) => r,
        None => return
    };
    println!("Found client.");
    init_stream(toggle.clone(), stream);
}

fn init_stream(toggle: Arc<AtomicBool>, stream: TcpStream) {
    stream.set_nonblocking(true).expect("should set to non blocking");
    // Read thread.
    let mut s_copy = stream.try_clone().expect("should clone server stream");
    let t_copy = toggle.clone();
    let read_thread = thread::spawn(move ||{
        while t_copy.load(Ordering::SeqCst) {
            let mut buffer = [0; 1024];
            let data = match s_copy.read(&mut buffer) {
                Ok(r) => r,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                },
                Err(e) => panic!("encountered IO error: {e}")
            };
            if data > 0 {
                let msg = String::from_utf8((&mut buffer[..data]).to_vec()).expect("should convert buffer to string");
                println!("Other -> {}", msg);
            }
        }
    });

    // Write thread.
    let mut s_copy = stream.try_clone().expect("should clone server stream");
    let t_copy = toggle.clone();
    let write_thread = thread::spawn(move ||{
        while t_copy.load(Ordering::SeqCst) {
            let mut line = String::new();
            let num_b = std::io::stdin().read_line(&mut line).expect("should read input into line");
            if num_b > 0 {
                s_copy.write(line.as_bytes()).expect("should write string to stream");
                println!("You -> {}", line);
            }
            thread::sleep(time::Duration::from_millis(500))
        }
    });

    read_thread.join().expect("should join read thread");
    write_thread.join().expect("should join write thread");
}