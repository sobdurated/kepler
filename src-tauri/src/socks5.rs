use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error};



const SOCKS_VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01; // RFC 1929

const AUTH_NONE: u8 = 0x00;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;

const REP_SUCCESS: u8 = 0x00;




#[derive(Debug)]
pub enum Socks5Error {
    Io(std::io::Error),
    AuthMethodRejected,
    AuthFailed,
    RequestFailed(u8),
    ProtocolError(String),
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "SOCKS5 I/O error: {}", e),
            Self::AuthMethodRejected => write!(f, "SOCKS5 server rejected all auth methods"),
            Self::AuthFailed => write!(f, "SOCKS5 username/password auth failed"),
            Self::RequestFailed(code) => write!(f, "SOCKS5 request failed (reply=0x{:02x}): {}", code, reply_message(*code)),
            Self::ProtocolError(msg) => write!(f, "SOCKS5 protocol error: {}", msg),
        }
    }
}

impl From<std::io::Error> for Socks5Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// maps reply code to msg
fn reply_message(code: u8) -> &'static str {
    match code {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}




async fn read_socks5_response(stream: &mut TcpStream) -> Result<(u8, u8, Ipv4Addr, u16), Socks5Error> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    
    let ver = header[0];
    let rep = header[1];
    let atyp = header[3];
    
    if ver != SOCKS_VERSION {
        return Err(Socks5Error::ProtocolError(format!(
            "expected SOCKS5 response version, got 0x{:02x}",
            ver
        )));
    }
    
    let (ip, port) = match atyp {
        0x01 => { // IPv4
            let mut addr_port = [0u8; 6];
            stream.read_exact(&mut addr_port).await?;
            let ip = Ipv4Addr::new(addr_port[0], addr_port[1], addr_port[2], addr_port[3]);
            let port = u16::from_be_bytes([addr_port[4], addr_port[5]]);
            (ip, port)
        }
        0x03 => { // Domain name
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain_port = vec![0u8; len + 2];
            stream.read_exact(&mut domain_port).await?;
            let port = u16::from_be_bytes([domain_port[len], domain_port[len + 1]]);
            (Ipv4Addr::new(0, 0, 0, 0), port)
        }
        0x04 => { // IPv6
            let mut addr_port = [0u8; 18];
            stream.read_exact(&mut addr_port).await?;
            let port = u16::from_be_bytes([addr_port[16], addr_port[17]]);
            (Ipv4Addr::new(0, 0, 0, 0), port)
        }
        other => {
            return Err(Socks5Error::ProtocolError(format!(
                "unsupported SOCKS5 address type 0x{:02x}",
                other
            )));
        }
    };
    
    Ok((ver, rep, ip, port))
}

pub async fn socks5_connect(
    proxy_addr: &str,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<TcpStream, Socks5Error> {
    debug!(
        proxy = proxy_addr,
        dest = %format!("{}:{}", dest_ip, dest_port),
        "SOCKS5 CONNECT"
    );

    let mut stream = TcpStream::connect(proxy_addr).await?;

    // auth handshake
    socks5_handshake(&mut stream, username, password).await?;

    // send connect cmd
    let mut req = Vec::with_capacity(10);
    req.push(SOCKS_VERSION);
    req.push(CMD_CONNECT);
    req.push(0x00);
    req.push(ATYP_IPV4);
    req.extend_from_slice(&dest_ip.octets());
    req.extend_from_slice(&dest_port.to_be_bytes());

    stream.write_all(&req).await?;

    // read response
    let (_ver, rep, _ip, _port) = read_socks5_response(&mut stream).await?;

    if rep != REP_SUCCESS {
        return Err(Socks5Error::RequestFailed(rep));
    }

    debug!("SOCKS5 CONNECT succeeded");
    Ok(stream)
}



pub struct UdpAssociation {
    pub relay_addr: SocketAddrV4,
    // must keep tcp stream open for relay to work
    pub control_stream: TcpStream,
}


pub async fn socks5_udp_associate(
    proxy_addr: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<UdpAssociation, Socks5Error> {
    debug!(proxy = proxy_addr, "SOCKS5 UDP ASSOCIATE");

    let mut stream = TcpStream::connect(proxy_addr).await?;


    socks5_handshake(&mut stream, username, password).await?;

    // req udp associate. dst_addr/port are 0 since dynamic flows
    let req = [
        SOCKS_VERSION, CMD_UDP_ASSOCIATE, 0x00,
        ATYP_IPV4,
        0, 0, 0, 0,
        0, 0,
    ];
    stream.write_all(&req).await?;


    let (_ver, rep, relay_ip, relay_port) = read_socks5_response(&mut stream).await?;

    if rep != REP_SUCCESS {
        return Err(Socks5Error::RequestFailed(rep));
    }


    // if unspecified, use remote proxy ip directly from peer_addr
    let relay_ip = if relay_ip.is_unspecified() {
        match stream.peer_addr() {
            Ok(addr) => match addr.ip() {
                std::net::IpAddr::V4(ipv4) => ipv4,
                std::net::IpAddr::V6(_) => {
                    // fallback to parsing if ipv6 (rare)
                    proxy_addr
                        .split(':')
                        .next()
                        .and_then(|h| h.parse().ok())
                        .unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
                }
            },
            Err(_) => {
                proxy_addr
                    .split(':')
                    .next()
                    .and_then(|h| h.parse().ok())
                    .unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
            }
        }
    } else {
        relay_ip
    };

    let relay_addr = SocketAddrV4::new(relay_ip, relay_port);
    debug!(%relay_addr, "SOCKS5 UDP ASSOCIATE succeeded");

    Ok(UdpAssociation {
        relay_addr,
        control_stream: stream,
    })
}

// wraps payload in socks5 udp header
pub fn encapsulate_udp(dest_ip: Ipv4Addr, dest_port: u16, data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(10 + data.len());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(0x00);
    pkt.push(ATYP_IPV4);
    pkt.extend_from_slice(&dest_ip.octets());
    pkt.extend_from_slice(&dest_port.to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}

// parses/strips header
pub fn decapsulate_udp(pkt: &[u8]) -> Option<(Ipv4Addr, u16, &[u8])> {
    if pkt.len() < 10 {
        return None;
    }

    let atyp = pkt[3];
    if atyp != ATYP_IPV4 {
        // ipv4 only for now
        return None;
    }

    let ip = Ipv4Addr::new(pkt[4], pkt[5], pkt[6], pkt[7]);
    let port = u16::from_be_bytes([pkt[8], pkt[9]]);
    let data = &pkt[10..];

    Some((ip, port, data))
}




async fn socks5_handshake(
    stream: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), Socks5Error> {
    let has_creds = username.is_some() && password.is_some();


    if has_creds {
        // offer both no-auth and user/pass
        stream
            .write_all(&[SOCKS_VERSION, 2, AUTH_NONE, AUTH_USERNAME_PASSWORD])
            .await?;
    } else {
        // only offer no-auth
        stream.write_all(&[SOCKS_VERSION, 1, AUTH_NONE]).await?;
    }


    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;

    if resp[0] != SOCKS_VERSION {
        return Err(Socks5Error::ProtocolError(format!(
            "expected SOCKS5, got version 0x{:02x}",
            resp[0]
        )));
    }

    match resp[1] {
        AUTH_NONE => {
            debug!("SOCKS5 auth: none required");
            Ok(())
        }

        AUTH_USERNAME_PASSWORD => {
            let user = username.ok_or(Socks5Error::AuthFailed)?;
            let pass = password.ok_or(Socks5Error::AuthFailed)?;

            debug!("SOCKS5 auth: username/password");


            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(AUTH_VERSION);
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());

            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;

            if auth_resp[1] != 0x00 {
                error!("SOCKS5 auth failed (status=0x{:02x})", auth_resp[1]);
                return Err(Socks5Error::AuthFailed);
            }

            debug!("SOCKS5 auth succeeded");
            Ok(())
        }

        AUTH_NO_ACCEPTABLE => Err(Socks5Error::AuthMethodRejected),

        other => Err(Socks5Error::ProtocolError(format!(
            "unknown auth method 0x{:02x}",
            other
        ))),
    }
}
