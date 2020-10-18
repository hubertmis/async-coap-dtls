use std::net::{UdpSocket, SocketAddr};
use std::io::{Read, Write};
use tokio_io::{AsyncRead,AsyncWrite};
use futures::task::Context;
use futures::Poll;
use std::pin::Pin;

use log::trace;

#[derive(Debug)]
pub struct UdpChannel {
    local_socket: UdpSocket,
    remote_addr: SocketAddr,
}

impl Read for UdpChannel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        trace!("Reading from {:?}", self.remote_addr);
        self.local_socket.recv(buf)
    }
}

impl Write for UdpChannel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        trace!("Writing to {:?}", self.remote_addr);
        self.local_socket.send_to(buf, self.remote_addr)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl AsyncRead for UdpChannel {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        Poll::from(self.local_socket.recv(buf))
    }
}

impl AsyncWrite for UdpChannel {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let addr = self.remote_addr;
        Poll::from(self.local_socket.send_to(buf, addr))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::from(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::from(Ok(()))
    }
}

impl UdpChannel {
    pub fn new(local_socket: UdpSocket, remote_addr: SocketAddr) -> UdpChannel {
        local_socket.set_read_timeout(Some(std::time::Duration::from_secs(1)));

        UdpChannel {
            local_socket,
            remote_addr
        }
    }
}
