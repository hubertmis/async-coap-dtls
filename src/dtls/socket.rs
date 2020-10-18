use openssl::ssl::{SslStream, ShutdownState};
use std::sync::{Arc, RwLock};
use std::io::{Write, Read};
use futures::Poll;
use std::net::{SocketAddr, UdpSocket};

use log::trace;

use super::channel::UdpChannel;

pub trait DtlsSocket {

    fn get_socket(&self) -> UdpSocket;

    fn get_channel(&self, remote_addr: SocketAddr) -> Result<Arc<RwLock<SslStream<UdpChannel>>>, std::io::Error>;

    fn free_channel(&self, remote_addr: SocketAddr);

    fn send(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        trace!("In send....");
        let channel = self.get_channel(addr).unwrap();
        channel.clone().write().unwrap().write(buf)
    }

    fn receive(&self, buf: &mut [u8]) -> Poll<Result<(usize, SocketAddr, Option<SocketAddr>), std::io::Error>> {
        loop {
            trace!("In receive...");
            let mut peek_buf = [0; 10];
            match self.get_socket().peek_from(&mut peek_buf) {
                Ok((_, from)) => {
                    let channel: Arc<RwLock<SslStream<UdpChannel>>>;
                    
                    match self.get_channel(from) {
                        Ok(ch) => channel = ch,
                        Err(_) => continue,
                    }

                    let size = channel.clone().write().unwrap().read(buf)?;
                    if size > 0 {
                        trace!("Received {} bytes", size);
                        return Poll::Ready(Ok((size, from, None)))
                    } else {
                        trace!("Received 0 bytes. Shutdown state: {:?}", channel.clone().write().unwrap().get_shutdown());
                        if channel.clone().write().unwrap().get_shutdown() == ShutdownState::RECEIVED {
                            channel.clone().write().unwrap().shutdown();
                            self.free_channel(from);
                        }
                        continue;
                    }
                },
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        continue;
                        //return Poll::Pending;
                    }
                    _ => return Poll::Ready(Err(e)),
                },
            }
        }
    }
}

macro_rules! dtls_socket {
    ($struct_type: ty) => {
        impl Unpin for $struct_type {}

        impl AsyncDatagramSocket for $struct_type {}

        impl DatagramSocketTypes for $struct_type {
            type SocketAddr = std::net::SocketAddr;
            type Error = std::io::Error;

            fn local_addr(&self) -> result::Result<Self::SocketAddr, Self::Error> {
                self.local_socket.local_addr()
            }

            fn lookup_host(
                host: &str,
                port: u16,
            ) -> result::Result<std::vec::IntoIter<Self::SocketAddr>, Self::Error>
                where
                    Self: Sized,
            {
                if host == ALL_COAP_DEVICES_HOSTNAME {
                    Ok(vec![
                        SocketAddr::V6(SocketAddrV6::new(
                            "FF02:0:0:0:0:0:0:FD".parse().unwrap(),
                            port,
                            0,
                            0,
                        )),
                        SocketAddr::V4(SocketAddrV4::new("224.0.1.187".parse().unwrap(), port)),
                        SocketAddr::V6(SocketAddrV6::new(
                            "FF03:0:0:0:0:0:0:FD".parse().unwrap(),
                            port,
                            0,
                            0,
                        )),
                    ]
                        .into_iter())
                } else {
                    (host, port).to_socket_addrs()
                }
            }
        }

        impl AsyncSendTo for $struct_type {
            fn poll_send_to<B>(
                self: Pin<&Self>,
                _: &mut Context<'_>,
                buf: &[u8],
                addr: B,
            ) -> Poll<Result<usize, Self::Error>>
                where
                    B: ToSocketAddrs<SocketAddr = Self::SocketAddr, Error = Self::Error>,
            {
                if let Some(addr) = addr.to_socket_addrs()?.next() {
                    match self.send(buf, addr) {
                        Ok(written) => Poll::Ready(Ok(written)),
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                Poll::Pending
                            } else {
                                Poll::Ready(Err(e))
                            }
                        }
                    }
                } else {
                    Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "Address lookup failed",
                    )))
                }
            }

            fn send_to<B>(& self, buf: &[u8], addr: B) -> Result<usize, Self::Error>
                where
                    B: ToSocketAddrs<SocketAddr = Self::SocketAddr, Error = Self::Error>,
            {
                if let Some(addr) = addr.to_socket_addrs()?.next() {
                    trace!("In acceptor send_to {:?}: {:?}", addr, buf);
                    self.send(buf, addr)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "Address lookup failed",
                    ))
                }
            }
        }

        impl AsyncRecvFrom for $struct_type {
            fn poll_recv_from(
                self: Pin<&Self>,
                _: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<Result<(usize, Self::SocketAddr, Option<Self::SocketAddr>), Self::Error>> {
                self.receive(buf)
            }
        }

        impl MulticastSocket for $struct_type {
            type IpAddr = std::net::IpAddr;

            fn join_multicast<A>(&self, _addr: A) -> Result<(), Self::Error> where
                A: std::convert::Into<Self::IpAddr> {
                unimplemented!()
            }

            fn leave_multicast<A>(&self, _addr: A) -> Result<(), Self::Error> where
                A: std::convert::Into<Self::IpAddr> {
                unimplemented!()
            }
        }
    }
}

