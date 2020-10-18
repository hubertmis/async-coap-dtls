use futures::task::Context;
use futures::Poll;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::pin::Pin;

use std::collections::HashMap;
use openssl::ssl::{SslStream, SslConnector};

use std::result;
use async_coap::datagram::{AsyncDatagramSocket, DatagramSocketTypes, AsyncSendTo, AsyncRecvFrom, MulticastSocket};
use async_coap::{ALL_COAP_DEVICES_HOSTNAME, ToSocketAddrs};
use std::collections::hash_map::Entry;
use std::sync::{Arc, RwLock};

use log::trace;

use super::channel::UdpChannel;
use super::socket::*;

pub struct DtlsConnectorSocket {
    local_socket: UdpSocket,
    connector: SslConnector,
    streams: Arc<RwLock<HashMap<SocketAddr, Arc<RwLock<SslStream<UdpChannel>>>>>>
}

impl DtlsConnectorSocket {

    pub fn new(local_socket: UdpSocket, connector: SslConnector) -> Self {

        trace!("Creating connector socket...");

        DtlsConnectorSocket {
            local_socket,
            connector,
            streams: Arc::new(RwLock::new(HashMap::new()))
        }
    }
}

impl DtlsSocket for DtlsConnectorSocket {

    fn get_socket(&self) -> UdpSocket {
        self.local_socket.try_clone().unwrap()
    }

    fn get_channel(&self, remote_addr: SocketAddr) -> Result<Arc<RwLock<SslStream<UdpChannel>>>, std::io::Error> {
        trace!("Getting connector channel for {:?}", remote_addr);
        let channel = match self.streams.write().unwrap().entry(remote_addr.clone()) {
            Entry::Vacant(entry) => {
                trace!("No entry found, creating new one...");
                let socket = self.local_socket.try_clone().unwrap();
                trace!("Creating channel...");
                let channel = UdpChannel::new(socket, remote_addr.clone());
                trace!("Creating connection stream...");
                let conn = self.connector.connect("127.0.0.1",channel).unwrap();
                trace!("Creating arced stream");
                let stream = Arc::new( RwLock::new(conn));
                trace!("Connector stream created with {:?}", stream);
                entry.insert(stream).clone()
            }
            // Cache hit - return value
            Entry::Occupied(entry) => {
                entry.get().clone()
            }
        };
        trace!("Got connector channel {:?}", channel);
        Ok(channel)
    }

    fn free_channel(&self, remote_addr: SocketAddr) {
        // TODO
    }
}

dtls_socket!(DtlsConnectorSocket);




