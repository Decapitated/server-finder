use std::{net::{Ipv4Addr, SocketAddrV4, UdpSocket, TcpStream, TcpListener}, io::{self, ErrorKind, Read, Write}, thread::{self, JoinHandle}, time, sync::{atomic::{AtomicBool, Ordering, AtomicU16}, Arc}};
use rand::rngs::ThreadRng;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme, pkcs8::{EncodePublicKey, DecodePublicKey}};
use urlencoding;

pub fn find_server(group_addr: Ipv4Addr, group_port: u16,
                   phrase: String, secret: String) -> io::Result<TcpStream> {
    // Setup multicast socket for listening.
    let socket_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), group_port);
    let interface_addr = Ipv4Addr::new(0, 0, 0, 0); // Use system default.
    let socket = UdpSocket::bind(socket_addr).expect("should bind udp_socket");
    socket.join_multicast_v4(&group_addr, &interface_addr).expect("should join group");
    socket.set_nonblocking(true).expect("should set nonblocking");
    // Listen for messages, then verify; returning the address for the server.
    let server_addr: SocketAddrV4 = loop {
        let mut buffer = [0; 1024];
        let (data, origin) = match socket.recv_from(&mut buffer) {
            Ok(r) => r,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                continue;
            },
            Err(e) => {
                panic!("{}", e);
            }
        };
        let msg = String::from_utf8((&mut buffer[..data]).to_vec()).unwrap();
        println!("[{}] {}", origin, msg); // #Debug
        let mut split = msg.split(":");
        let parsed_msg: io::Result<(String, u16)> = {
            let key_phrase = String::from(split.next().unwrap());
            let port = String::from(split.next().unwrap()).parse::<u16>().expect("should parse port into u16");
            Ok((key_phrase, port))
        };
        let (key_phrase, port) = match parsed_msg {
            Ok(r) => r,
            Err(e) => {
                println!("{}", e);
                continue;
            }
        };
        if key_phrase != phrase {
            continue;
        }
        let ip = match origin.ip().to_string().parse::<Ipv4Addr>() {
            Ok(r) => r,
            Err(e) => {
                println!("{}", e);
                continue;
            }
        };
        println!("Server Found @ {}:{}", ip, port); // #Debug
        break SocketAddrV4::new(ip, port);
    };
    let mut stream = TcpStream::connect(server_addr).expect("should connect to server");
    stream.write(secret.as_bytes())?;
    Ok(stream)
}

pub fn find_client(toggle: Arc<AtomicBool>,
                   group_addr: Ipv4Addr, group_port: u16,
                   phrase: String, secret: String) -> io::Result<TcpStream> { //TcpStream
    let tcp_port: Arc<AtomicU16> = Arc::new(AtomicU16::new(0));

    let toggle_clone = toggle.clone();
    let port_clone = tcp_port.clone();
    let await_thread: JoinHandle<TcpStream> = thread::spawn(move ||{
        let client = match await_client(secret, toggle_clone, port_clone) {
            Ok(r) => r,
            _ => panic!("No client found.")
        };
        return client;
    });

    let toggle_clone = toggle.clone();
    let port_clone = tcp_port.clone();
    thread::spawn(move ||{
        // Setup multicast socket for casting.
        let socket_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let socket = UdpSocket::bind(socket_addr).expect("should bind udp_socket");
        socket.set_multicast_loop_v4(false).expect("should prevent loop");
        while toggle_clone.load(Ordering::SeqCst) {
            socket.send_to(
                format!("{}:{}",
                    urlencoding::encode(phrase.as_str()),
                    port_clone.load(Ordering::SeqCst)).as_bytes(),
                SocketAddrV4::new(group_addr, group_port)).expect("should create a V4 address");
            thread::sleep(time::Duration::from_secs(1));
        }
    });
    /*loop {
        socket.send_to(TCP_PORT.to_string().as_bytes(), SocketAddrV4::new(GROUP_ADDR, GROUP_PORT))?;
        thread::sleep(time::Duration::from_secs(1));
    }*/
    let client = await_thread.join().expect("should be client stream");
    toggle.store(false, Ordering::SeqCst);
    Ok(client)
}

fn await_client(secret: String, toggle: Arc<AtomicBool>, tcp_port:Arc<AtomicU16>) -> io::Result<TcpStream> {
    let socket_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
    let listener = TcpListener::bind(socket_addr)?;
    tcp_port.store(listener.local_addr()?.port(), Ordering::SeqCst);
    listener.set_nonblocking(true).expect("should set non-blocking");
    let mut client: Option<TcpStream> = None;
    while client.is_none() && toggle.load(Ordering::SeqCst) {
        let (mut stream, _) = match listener.accept() {
            Ok(r) => r,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            },
            Err(e) => panic!("encountered IO error: {e}")
        };
        stream.set_nonblocking(false).expect("should set stream to nonblocking");
        let mut buffer = [0; 1024];
        let data = match stream.read(&mut buffer) {
            Ok(r) => r,
            Err(_) => continue
        };
        let msg = String::from_utf8((&mut buffer[..data]).to_vec()).unwrap();
        if msg == secret {
            println!("Secret Received: {}", msg); // #Debug
            client = Some(stream);
        } else {
            continue;
        }
    }
    Ok(client.expect("should be stream"))
}

// let pub_key = RsaPublicKey::from_public_key_pem(split.next().unwrap()).expect("should parse pem into public key");

/* Example
    let (k_private, k_public, mut rng) = match server_finder::generate_keys() {
        Ok(n) => n,
        Err(e) => {
            panic!("{}", e);
        }
    };
 */
fn generate_keys() -> io::Result<(RsaPrivateKey, RsaPublicKey, ThreadRng)> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("should generate a private key");
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((priv_key, pub_key, rng))
}

/*
    pub fn add(left: usize, right: usize) -> usize {
        left + right
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn it_works() {
            let result = add(2, 2);
            assert_eq!(result, 4);
        }
    }
 */