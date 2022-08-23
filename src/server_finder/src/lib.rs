use std::{net::{Ipv4Addr, SocketAddrV4, UdpSocket, TcpStream}, io::{self, ErrorKind}, thread, time};
use rand::rngs::ThreadRng;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme, pkcs8::{EncodePublicKey, DecodePublicKey}};
use urlencoding;

pub fn find_server(group_addr: Ipv4Addr, group_port: u16, phrase: String) -> io::Result<()> { //TcpStream
    // Setup multicast socket for listening.
    let socket_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), group_port);
    let interface_addr = Ipv4Addr::new(0, 0, 0, 0); // Use system default.
    let socket = UdpSocket::bind(socket_addr)?;
    socket.join_multicast_v4(&group_addr, &interface_addr)?;
    socket.set_nonblocking(true)?;
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
        break SocketAddrV4::new(ip, port);
    };
    println!("{}", server_addr);
    Ok(())
}

pub fn find_client(group_addr: Ipv4Addr, group_port: u16, tcp_port: u16, phrase: String, secret: String) -> io::Result<()> { //TcpStream
    // Setup multicast socket for casting.
    let socket_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
    let socket = UdpSocket::bind(socket_addr)?;
    socket.set_multicast_loop_v4(false)?;
    /*loop {
        socket.send_to(TCP_PORT.to_string().as_bytes(), SocketAddrV4::new(GROUP_ADDR, GROUP_PORT))?;
        thread::sleep(time::Duration::from_secs(1));
    }*/
    for _ in 1..10 {
        socket.send_to(format!("{}:{}", urlencoding::encode(phrase.as_str()), tcp_port).as_bytes(), SocketAddrV4::new(group_addr, group_port))?;
        thread::sleep(time::Duration::from_secs(1));
    }
    Ok(())
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