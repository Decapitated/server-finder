use std::{net::{Ipv4Addr, SocketAddrV4, UdpSocket}, io::{self, ErrorKind}, thread, time, sync::{atomic::{AtomicBool, Ordering}, Arc}};
use ctrlc;

static GROUP_ADDR: Ipv4Addr = Ipv4Addr::new(230, 0, 0, 1);
static GROUP_PORT: u16 = 5454;
static TCP_PORT: u16 = 5469;

fn listen(running: Arc<AtomicBool>) -> io::Result<()> {
    let socket_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), GROUP_PORT);
    // Use system default.
    let interface_addr = Ipv4Addr::new(0, 0, 0, 0);
    let socket = UdpSocket::bind(socket_addr)?;
    println!("Listening on: {}", socket.local_addr().unwrap());
    socket.join_multicast_v4(&GROUP_ADDR, &interface_addr)?;
    socket.set_nonblocking(true)?;
    //socket.set_read_timeout(Some(time::Duration::from_secs(1))).expect("set_read_timeout call failed");
    while running.load(Ordering::SeqCst) != false {
        let mut buffer = [0; 1024];
        let (data, origin) = match socket.recv_from(&mut buffer) {
            Ok(r) => r,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                continue;
            },
            Err(e) => {
                println!("{}", e);
                break;
            }
        };
        let buffer = &mut buffer[..data];
        let msg = String::from_utf8(buffer.to_vec()).unwrap();
        println!("Server received: {} from {}", msg, origin);
    }
    println!("Listen exiting.");
    Ok(())
}

fn cast(running: Arc<AtomicBool>) -> io::Result<()> {
    let socket_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
    let socket = UdpSocket::bind(socket_addr)?;
    socket.set_multicast_loop_v4(false)?;
    while running.load(Ordering::SeqCst) != false {
        socket.send_to(TCP_PORT.to_string().as_bytes(), SocketAddrV4::new(GROUP_ADDR, GROUP_PORT))?;
        thread::sleep(time::Duration::from_secs(1));
    }
    println!("Cast exiting.");
    Ok(())
}

fn main() {
    let running = Arc::new(AtomicBool::new(true));

    let run_clone = running.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl+C");
        run_clone.store(false, Ordering::SeqCst);
    }).expect("Should set running to false.");

    let run_clone = running.clone();
    let listen_thread = thread::spawn(move ||{
        listen(run_clone).expect("Should be listening.");
    });

    let run_clone = running.clone();
    let cast_thread = thread::spawn(move ||{
        cast(run_clone).expect("Should be casting.");
    });

    listen_thread.join().expect("Listen thread should join.");
    cast_thread.join().expect("Cast thread should join.");
}