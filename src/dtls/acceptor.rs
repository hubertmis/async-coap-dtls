use futures::task::Context;
use futures::Poll;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::pin::Pin;

use std::collections::HashMap;
use openssl::ssl::{SslStream, SslAcceptor};

use std::result;
use async_coap::datagram::{AsyncDatagramSocket, DatagramSocketTypes, AsyncSendTo, AsyncRecvFrom, MulticastSocket};
use async_coap::{ALL_COAP_DEVICES_HOSTNAME, ToSocketAddrs};
use std::collections::hash_map::Entry;
use std::sync::{Arc, RwLock};

use log::trace;

use super::channel::UdpChannel;
use super::socket::DtlsSocket;

pub struct DtlsAcceptorSocket {
    local_socket: UdpSocket,
    acceptor: SslAcceptor,
    streams: Arc<RwLock<HashMap<SocketAddr, Arc<RwLock<SslStream<UdpChannel>>>>>>
}

impl DtlsAcceptorSocket {

    pub fn new(local_socket: UdpSocket, acceptor: SslAcceptor) -> Self {

        trace!("Creating acceptor dtls socket...");

        DtlsAcceptorSocket {
            local_socket,
            acceptor,
            streams: Arc::new(RwLock::new(HashMap::new()))
        }
    }
}

impl DtlsSocket for DtlsAcceptorSocket {

    fn get_socket(&self) -> UdpSocket {
        trace!("Clonning socket: {:?}", self.local_socket);
        self.local_socket.try_clone().unwrap()
    }

    fn get_channel(&self, remote_addr: SocketAddr) -> Result<Arc<RwLock<SslStream<UdpChannel>>>, std::io::Error> {
        trace!("Getting acceptor channel for {:?}", remote_addr);
        match self.streams.write().unwrap().entry(remote_addr.clone()) {
            Entry::Vacant(entry) => {
                trace!("Acceptor channel vacant");
                let socket = self.local_socket.try_clone().unwrap();
                let channel = UdpChannel::new(socket, remote_addr.clone());
                let stream = Arc::new( RwLock::new(self.acceptor.accept(channel).map_err(
                            |_| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "DTLS connection refulsed"))?));
                Ok(entry.insert(stream).clone())
            }
            // Cache hit - return value
            Entry::Occupied(entry) => {
                trace!("Acceptor channel occupied");
                Ok(entry.get().clone())
            }
        }
    }

    fn free_channel(&self, remote_addr: SocketAddr) {
        trace!("Freeing acceptor channel for {:?}", remote_addr);

        match self.streams.write().unwrap().entry(remote_addr.clone()) {
            Entry::Vacant(entry) => {
                trace!("Acceptor channel vacant. Do nothing");
            }
            Entry::Occupied(entry) => {
                trace!("Acceptor channel occupied. Remove it");
                entry.remove();
            }
        }
    }
}

dtls_socket!(DtlsAcceptorSocket);



