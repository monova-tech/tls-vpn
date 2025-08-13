use crate::protocol::Protocol;

use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::{DashMap, DashSet};
use pnet::packet::Packet;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use pnet::packet::ip::IpNextHeaderProtocols;
use uuid::Uuid;

pub type NatResult<T> = Result<T, String>;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct PacketMetadata {
    pub source_address: IpAddr,
    pub destination_address: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone)]
pub struct NatConfig {
    pub source_ipv4: Ipv4Addr,
    pub source_ipv6: Option<Ipv6Addr>,
    pub udp_inactive_expiry_duration: Duration,
    pub tcp_inactive_expiry_duration: Duration,
}

impl NatConfig {
    pub fn default(source_ipv4: Ipv4Addr) -> Self {
        Self {
            source_ipv4,
            source_ipv6: None,
            udp_inactive_expiry_duration: Duration::from_secs(30),
            tcp_inactive_expiry_duration: Duration::from_secs(5 * 60),
        }
    }

    pub fn ipv6_interface(mut self, interface_ipv6: Ipv6Addr) -> Self {
        self.source_ipv6 = Some(interface_ipv6);
        self
    }
}

pub type PacketRxIdentifer = Uuid;

#[derive(Debug, Clone)]
pub struct Nat {
    /// Used to track the original metadata of a packet.
    translated_to_original_map: Arc<DashMap<PacketMetadata, PacketMetadata>>,
    /// Used to track the translated metadata of a packet from translated metadata.
    original_to_translated_map: Arc<DashMap<PacketMetadata, PacketMetadata>>,
    /// Used to send packets to the correct client.
    translated_to_rx_identifier_map: Arc<DashMap<PacketMetadata, PacketRxIdentifer>>,
    /// Used to track inactive connections. Original packet information is used
    /// as key. If target server replies, this map value is updated.
    original_to_last_activity: Arc<DashMap<PacketMetadata, Instant>>,
    /// Used to track used tcp source ports.
    tcp_source_ports: Arc<DashSet<u16>>,
    /// Used to track used tcp source ports.
    udp_source_ports: Arc<DashSet<u16>>,
    /// Configuration for NAT.
    config: Arc<NatConfig>,
}

impl Nat {
    pub fn with_config(config: NatConfig) -> Self {
        Self {
            translated_to_original_map: Arc::new(DashMap::new()),
            original_to_translated_map: Arc::new(DashMap::new()),
            translated_to_rx_identifier_map: Arc::new(DashMap::new()),
            original_to_last_activity: Arc::new(DashMap::new()),
            tcp_source_ports: Arc::new(DashSet::new()),
            udp_source_ports: Arc::new(DashSet::new()),
            config: Arc::new(config),
        }
    }

    fn ipv4_packet_metadata(ip_packet: &[u8]) -> NatResult<PacketMetadata> {
        let ipv4_packet = match Ipv4Packet::new(ip_packet) {
            Some(packet) => packet,
            None => {
                let error_message =
                    "Invalid IPV4 packet received. Could not extract metadata.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        let ipv4_payload = ipv4_packet.payload();
        let source_address = IpAddr::V4(ipv4_packet.get_source());
        let destination_address = IpAddr::V4(ipv4_packet.get_destination());
        let protocol: Protocol;
        let source_port: u16;
        let destination_port: u16;

        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                protocol = Protocol::TCP;

                let tcp_packet = match TcpPacket::new(ipv4_payload) {
                    Some(packet) => packet,
                    None => {
                        let error_message = "Invalid TCP packet is received. Could not find
                            parse the packet"
                            .to_string();
                        crate::logging::debug(&error_message);
                        return Err(error_message);
                    }
                };

                source_port = tcp_packet.get_source();
                destination_port = tcp_packet.get_destination();
            }

            IpNextHeaderProtocols::Udp => {
                protocol = Protocol::UDP;

                let udp_packet = match UdpPacket::new(ipv4_payload) {
                    Some(packet) => packet,
                    None => {
                        let error_message = "Invalid UDP packet is received. Could not parge the
                            packet"
                            .to_string();
                        crate::logging::debug(&error_message);
                        return Err(error_message);
                    }
                };

                source_port = udp_packet.get_source();
                destination_port = udp_packet.get_destination();
            }

            protcol_version => {
                let error_message = format!(
                    "Invalid protocol version {}. Can't create packet
                    metadata.",
                    protcol_version
                );
                return Err(error_message);
            }
        }

        Ok(PacketMetadata {
            source_address,
            destination_address,
            source_port,
            destination_port,
            protocol,
        })
    }

    fn ipv6_packet_metadata(ip_packet: &[u8]) -> NatResult<PacketMetadata> {
        let ipv6_packet = match Ipv6Packet::new(ip_packet) {
            Some(packet) => packet,
            None => {
                let error_message =
                    "Invalid IPV6 packet received. Could not create metadata".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        let ipv6_payload = ipv6_packet.payload();
        let source_address = IpAddr::V6(ipv6_packet.get_source());
        let destination_address = IpAddr::V6(ipv6_packet.get_destination());
        let protocol: Protocol;
        let source_port: u16;
        let destination_port: u16;

        match ipv6_packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                protocol = Protocol::TCP;

                let tcp_packet = match TcpPacket::new(ipv6_payload) {
                    Some(packet) => packet,
                    None => {
                        let error_message = "Invalid TCP packet is received. Could not find
                            parse the packet"
                            .to_string();
                        crate::logging::debug(&error_message);
                        return Err(error_message);
                    }
                };

                source_port = tcp_packet.get_source();
                destination_port = tcp_packet.get_destination();
            }

            IpNextHeaderProtocols::Udp => {
                protocol = Protocol::UDP;

                let udp_packet = match UdpPacket::new(ipv6_payload) {
                    Some(packet) => packet,
                    None => {
                        let error_message = "Invalid UDP packet is received. Could not parse the
                            packet"
                            .to_string();
                        crate::logging::debug(&error_message);
                        return Err(error_message);
                    }
                };

                source_port = udp_packet.get_source();
                destination_port = udp_packet.get_destination();
            }

            protcol_version => {
                let error_message = format!(
                    "Invalid protocol version {}. Can't create packet
                    metadata.",
                    protcol_version
                );
                return Err(error_message);
            }
        }

        Ok(PacketMetadata {
            source_address,
            destination_address,
            source_port,
            destination_port,
            protocol,
        })
    }

    /// Generates a new source port for a new packet lineraly.
    /// If success, new unique source port is reserved in NAT mapping.
    fn request_new_source_port(&self, protocol: &Protocol) -> NatResult<u16> {
        for port_number in 1024..65535 {
            if protocol == &Protocol::TCP {
                if !self.tcp_source_ports.contains(&port_number) {
                    self.tcp_source_ports.insert(port_number);
                    return Ok(port_number);
                }
            } else {
                if !self.udp_source_ports.contains(&port_number) {
                    self.udp_source_ports.insert(port_number);
                    return Ok(port_number);
                }
            }
        }

        let error_message = "No slot is available for new source port.".to_string();
        crate::logging::debug(&error_message);
        Err(error_message)
    }

    fn routable_ipv4_packet(
        translated_packet_metadata: &PacketMetadata,
        mutable_ipv4_packet: &mut MutableIpv4Packet,
    ) -> NatResult<()> {
        let source_ipv4_address = match translated_packet_metadata.source_address {
            IpAddr::V4(address) => address,
            _ => {
                let error_message = "Could not create routable IPV4 packet. This function only
                    supports IPv4 address."
                    .to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        let destination_ipv4_address = match translated_packet_metadata.destination_address {
            IpAddr::V4(address) => address,
            _ => {
                let error_message = "Could not create routable IPV4 packet. This function only
                    supports IPv4 address."
                    .to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        mutable_ipv4_packet.set_source(source_ipv4_address);
        mutable_ipv4_packet.set_destination(destination_ipv4_address);
        mutable_ipv4_packet.set_checksum(0);
        let ip_checksum = ipv4::checksum(&mutable_ipv4_packet.to_immutable());
        mutable_ipv4_packet.set_checksum(ip_checksum);
        Ok(())
    }

    fn routable_ipv6_packet(
        translated_packet_metadata: &PacketMetadata,
        mutable_ipv6_packet: &mut MutableIpv6Packet,
    ) -> NatResult<()> {
        let source_ipv6_addr = match translated_packet_metadata.source_address {
            IpAddr::V6(address) => address,
            _ => {
                let error_message = "Could not create routable IPV6 packet. This function only
                    supports IPv6 address."
                    .to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        mutable_ipv6_packet.set_source(source_ipv6_addr);

        let destination_ipv6_addr = match translated_packet_metadata.source_address {
            IpAddr::V6(address) => address,
            _ => {
                let error_message = "Could not create routable IPV6 packet. This function only
                    supports IPv6 address."
                    .to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        mutable_ipv6_packet.set_source(source_ipv6_addr);
        mutable_ipv6_packet.set_destination(destination_ipv6_addr);
        Ok(())
    }

    fn routable_new_ipv4_tcp_packet(
        translated_packet_metadata: &PacketMetadata,
        mutable_tcp_packet: &mut MutableTcpPacket,
    ) -> NatResult<()> {
        let source_ipv4_addr = match translated_packet_metadata.source_address {
            IpAddr::V4(addr) => addr,
            _ => {
                let error_message = "The source address is not IPV4 address.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        let destination_ipv4_addr = match translated_packet_metadata.destination_address {
            IpAddr::V4(addr) => addr,
            _ => {
                let error_message = "The source address is not IPV4 address.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        mutable_tcp_packet.set_source(translated_packet_metadata.source_port);
        mutable_tcp_packet.set_destination(translated_packet_metadata.destination_port);
        mutable_tcp_packet.set_checksum(0);
        let checksum = tcp::ipv4_checksum(
            &mutable_tcp_packet.to_immutable(),
            &source_ipv4_addr,
            &destination_ipv4_addr,
        );
        mutable_tcp_packet.set_checksum(checksum);
        Ok(())
    }

    fn routable_new_ipv6_tcp_packet(
        translated_packet_metadata: &PacketMetadata,
        mutable_tcp_packet: &mut MutableTcpPacket,
    ) -> NatResult<()> {
        let source_ipv6_addr = match translated_packet_metadata.source_address {
            IpAddr::V6(addr) => addr,
            _ => {
                let error_message = "The source address is not IPV6 address.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        let destination_ipv6_addr = match translated_packet_metadata.destination_address {
            IpAddr::V6(addr) => addr,
            _ => {
                let error_message = "The source address is not IPV6 address.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        mutable_tcp_packet.set_source(translated_packet_metadata.source_port);
        mutable_tcp_packet.set_destination(translated_packet_metadata.destination_port);
        mutable_tcp_packet.set_checksum(0);
        let checksum = tcp::ipv6_checksum(
            &mutable_tcp_packet.to_immutable(),
            &source_ipv6_addr,
            &destination_ipv6_addr,
        );
        mutable_tcp_packet.set_checksum(checksum);
        Ok(())
    }

    fn routable_new_tcp_packet(
        translated_packet_metadata: &PacketMetadata,
        mutable_tcp_packet: &mut MutableTcpPacket,
    ) -> NatResult<()> {
        if translated_packet_metadata.source_address.is_ipv4() {
            Self::routable_new_ipv4_tcp_packet(translated_packet_metadata, mutable_tcp_packet)?;
        } else if translated_packet_metadata.source_address.is_ipv6() {
            Self::routable_new_ipv6_tcp_packet(translated_packet_metadata, mutable_tcp_packet)?;
        } else {
            let error_message =
                "Failed to create routable tcp packet for unknown version.".to_string();
            crate::logging::debug(&error_message);
            return Err(error_message);
        }

        Ok(())
    }

    fn routable_new_ipv4_udp_packet(
        translated_packet_metadata: &PacketMetadata,
        mutable_udp_packet: &mut MutableUdpPacket,
    ) -> NatResult<()> {
        let source_ipv4_addr = match translated_packet_metadata.source_address {
            IpAddr::V4(addr) => addr,
            _ => {
                let error_message = "The source address is not IPV4 address.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        let destination_ipv4_addr = match translated_packet_metadata.destination_address {
            IpAddr::V4(addr) => addr,
            _ => {
                let error_message = "The source address is not IPV4 address.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        mutable_udp_packet.set_source(translated_packet_metadata.source_port);
        mutable_udp_packet.set_destination(translated_packet_metadata.destination_port);
        mutable_udp_packet.set_checksum(0);
        let checksum = udp::ipv4_checksum(
            &mutable_udp_packet.to_immutable(),
            &source_ipv4_addr,
            &destination_ipv4_addr,
        );
        mutable_udp_packet.set_checksum(checksum);
        Ok(())
    }

    fn routable_new_ipv6_udp_packet(
        translated_packet_metadata: &PacketMetadata,
        mutable_udp_packet: &mut MutableUdpPacket,
    ) -> NatResult<()> {
        let source_ipv6_addr = match translated_packet_metadata.source_address {
            IpAddr::V6(addr) => addr,
            _ => {
                let error_message = "The source address is not IPV6 address.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        let destination_ipv6_addr = match translated_packet_metadata.destination_address {
            IpAddr::V6(addr) => addr,
            _ => {
                let error_message = "The source address is not IPV4 address.".to_string();
                crate::logging::debug(&error_message);
                return Err(error_message);
            }
        };

        mutable_udp_packet.set_source(translated_packet_metadata.source_port);
        mutable_udp_packet.set_destination(translated_packet_metadata.destination_port);
        mutable_udp_packet.set_checksum(0);
        let checksum = udp::ipv6_checksum(
            &mutable_udp_packet.to_immutable(),
            &source_ipv6_addr,
            &destination_ipv6_addr,
        );
        mutable_udp_packet.set_checksum(checksum);
        Ok(())
    }

    fn routable_new_udp_packet(
        translated_packet_metadata: &PacketMetadata,
        mutable_udp_packet: &mut MutableUdpPacket,
    ) -> NatResult<()> {
        if translated_packet_metadata.source_address.is_ipv4() {
            Self::routable_new_ipv4_udp_packet(translated_packet_metadata, mutable_udp_packet)?;
        } else if translated_packet_metadata.source_address.is_ipv6() {
            Self::routable_new_ipv6_udp_packet(translated_packet_metadata, mutable_udp_packet)?;
        } else {
            let error_message =
                "Failed to create routable UDP packet for unknown version.".to_string();
            crate::logging::debug(&error_message);
            return Err(error_message);
        }

        Ok(())
    }

    pub fn clear_mapping(
        &self,
        original_packet_metadata_hint: Option<&PacketMetadata>,
        translated_packet_metadata_hint: Option<&PacketMetadata>,
    ) -> bool {
        let original_metadata: PacketMetadata;
        let translated_metadata: PacketMetadata;

        if original_packet_metadata_hint.is_none() && translated_packet_metadata_hint.is_none() {
            return false;
        }

        if let Some(metadata) = original_packet_metadata_hint {
            original_metadata = metadata.clone();
            translated_metadata = match self.original_to_translated_map.get(&original_metadata) {
                Some(metadata) => metadata.clone(),
                None => {
                    return false;
                }
            };
        } else if let Some(metadata) = translated_packet_metadata_hint {
            translated_metadata = metadata.clone();
            original_metadata = match self.translated_to_original_map.get(&translated_metadata) {
                Some(metadata) => metadata.clone(),
                None => {
                    return false;
                }
            };
        } else {
            return false;
        }

        // These values may and may not exist in the NAT mapping.
        // Clear original mapping -> translated mapping and port
        self.original_to_translated_map.remove(&original_metadata);
        self.translated_to_original_map.remove(&translated_metadata);
        self.translated_to_rx_identifier_map
            .remove(&translated_metadata);

        // Remove ports
        let used_port_for_outbound_connection = translated_metadata.source_port;

        if original_metadata.protocol == Protocol::TCP {
            self.tcp_source_ports
                .remove(&used_port_for_outbound_connection);
        } else if original_metadata.protocol == Protocol::UDP {
            self.udp_source_ports
                .remove(&used_port_for_outbound_connection);
        }

        true
    }

    /// Generate new IP packet based on routing information provided.
    /// Adds new routing information as well as removes when necessary.
    fn route_packet_outbound(
        &self,
        original_packet_metadata: &PacketMetadata,
        translated_packet_metadata: &PacketMetadata,
        ip_packet: &[u8],
    ) -> NatResult<Vec<u8>> {
        let mut routable_packet = ip_packet.to_vec();
        let packet_payload;

        // Change source address and extract tcp/udp payload
        if original_packet_metadata.source_address.is_ipv4() {
            let mut mutable_ipv4_packet = match MutableIpv4Packet::new(&mut routable_packet) {
                Some(packet) => packet,
                None => {
                    let error_message = "Provided IP packet is not a valid packet. Failed to create
                        mutable IPV4 packet."
                        .to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

            Self::routable_ipv4_packet(translated_packet_metadata, &mut mutable_ipv4_packet)?;
            let ihl = mutable_ipv4_packet.get_header_length();
            let ipv4_payload_offset = ihl * 4; // Payload starts at ihl * 4
            packet_payload = &mut routable_packet[ipv4_payload_offset as usize..];
        } else if original_packet_metadata.source_address.is_ipv6() {
            let mut mutable_ipv6_packet = match MutableIpv6Packet::new(&mut routable_packet) {
                Some(packet) => packet,
                None => {
                    let error_message = "Provided IP packet is not a valid packet. Failed to create
                        mutable IPV6 packet."
                        .to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

            Self::routable_ipv6_packet(translated_packet_metadata, &mut mutable_ipv6_packet)?;
            let ipv6_header_size = 40;
            packet_payload = &mut routable_packet[ipv6_header_size as usize..];
        } else {
            let error_message = "Unknown IP version is specified in packet. This version is not
                supported."
                .to_string();
            crate::logging::debug(&error_message);
            return Err(error_message);
        }

        if original_packet_metadata.protocol == Protocol::TCP {
            let mut mutable_tcp_packet = match MutableTcpPacket::new(packet_payload) {
                Some(packet) => packet,
                None => {
                    let error_message = "Invalid TCP packet is received. Failed to create mutable
                        TCP packet."
                        .to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

            Self::routable_new_tcp_packet(translated_packet_metadata, &mut mutable_tcp_packet)?;

            // Cleanup reset connections from mapping.
            if mutable_tcp_packet.get_flags() == TcpFlags::RST {
                self.clear_mapping(
                    Some(original_packet_metadata),
                    Some(translated_packet_metadata),
                );
            }
        } else if original_packet_metadata.protocol == Protocol::UDP {
            let mut mutable_udp_packet = match MutableUdpPacket::new(packet_payload) {
                Some(packet) => packet,
                None => {
                    let error_message = "Invalid UDP packet is received. Failed to create mutable
                        UDP packet."
                        .to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

            Self::routable_new_udp_packet(translated_packet_metadata, &mut mutable_udp_packet)?;
        }

        Ok(routable_packet)
    }

    pub fn packet_metadata(ip_packet: &[u8]) -> NatResult<PacketMetadata> {
        if ip_packet.len() == 0 {
            let error_message =
                "Packet length is 0. Could not read internet protocol version.".to_string();
            crate::logging::debug(&error_message);
            return Err(error_message);
        }

        let ip_version = ip_packet[0] >> 4;
        if ip_version == 4 {
            return Ok(Self::ipv4_packet_metadata(ip_packet)?);
        } else if ip_version == 6 {
            return Ok(Self::ipv6_packet_metadata(ip_packet)?);
        }

        let error_message = format!(
            "Unhandled IP version: {}. Could not get packet metadata.",
            ip_version
        );
        crate::logging::debug(&error_message);
        return Err(error_message);
    }

    fn get_or_create_mapping_record(
        &self,
        rx_identifier: &PacketRxIdentifer,
        ip_packet: &[u8],
    ) -> NatResult<(PacketMetadata, PacketMetadata)> {
        let original_packet_metadata = Self::packet_metadata(ip_packet)?;

        // Used for original to translation packet metadata lookup.
        let translated_packet_metadata = match self
            .original_to_translated_map
            .get(&original_packet_metadata)
        {
            Some(packet_metadata) => packet_metadata.clone(),
            None => {
                let mut translation_metadata = original_packet_metadata.clone();
                if original_packet_metadata.source_address.is_ipv4() {
                    translation_metadata.source_address = IpAddr::V4(self.config.source_ipv4);
                } else {
                    if let Some(source_addr) = self.config.source_ipv6 {
                        translation_metadata.source_address = IpAddr::V6(source_addr);
                    } else {
                        let error_message =
                            "New routing for Ipv6 packet is requested but Ipv6 interface
                            is not configured for routing in Nat configuration.
                            "
                            .to_string();
                        crate::logging::debug(&error_message);
                        return Err(error_message);
                    }
                }

                translation_metadata.source_port =
                    self.request_new_source_port(&translation_metadata.protocol)?;
                self.original_to_translated_map.insert(
                    original_packet_metadata.clone(),
                    translation_metadata.clone(),
                );
                translation_metadata
            }
        };

        // Used for translation to original packet metadata lookup.
        match self
            .translated_to_original_map
            .get(&translated_packet_metadata)
        {
            None => {
                self.translated_to_original_map.insert(
                    translated_packet_metadata.clone(),
                    original_packet_metadata.clone(),
                );
            }
            _ => {}
        };

        match self
            .translated_to_rx_identifier_map
            .get(&translated_packet_metadata)
        {
            None => {
                self.translated_to_rx_identifier_map
                    .insert(translated_packet_metadata.clone(), rx_identifier.clone());
            }
            _ => {}
        }

        // New packet is routed through the NAT. Log this event.
        if let Some(mut last_activity) = self
            .original_to_last_activity
            .get_mut(&original_packet_metadata)
        {
            *last_activity = Instant::now();
        } else {
            let last_activity = Instant::now();
            self.original_to_last_activity
                .insert(original_packet_metadata.clone(), last_activity);
        }

        Ok((original_packet_metadata, translated_packet_metadata))
    }

    /// Returns new packet with different source address and source port.
    /// New source address and source port assignment is handled by the NAT table.
    /// Keeps this routing information in NAT table until it expires.
    pub fn route_target(
        &self,
        rx_identifier: &PacketRxIdentifer,
        ip_packet: &[u8],
    ) -> NatResult<Vec<u8>> {
        let (original_packet_metadata, translated_packet_metadata) =
            self.get_or_create_mapping_record(rx_identifier, ip_packet)?;

        // Generate new packet ready for routing.
        self.route_packet_outbound(
            &original_packet_metadata,
            &translated_packet_metadata,
            ip_packet,
        )
    }

    /// Returns translation packet metadata based on the response packet. It is just a lookup key
    /// to query original outbound packet metadata.
    pub fn translated_lookup_metadata_from_reply_packet_metadata(
        reply_packet_metadata: &PacketMetadata,
    ) -> NatResult<PacketMetadata> {
        let mut translated_lookup_metadata = reply_packet_metadata.clone();
        translated_lookup_metadata.source_address = reply_packet_metadata.destination_address;
        translated_lookup_metadata.destination_address = reply_packet_metadata.source_address;
        translated_lookup_metadata.source_port = reply_packet_metadata.destination_port;
        translated_lookup_metadata.destination_port = reply_packet_metadata.source_port;
        Ok(translated_lookup_metadata)
    }

    /// Uses translated packet metadata to query rx identifier.
    pub fn lookup_rx_identifier(
        &self,
        lookup_packet_metadata: &PacketMetadata,
    ) -> Option<PacketRxIdentifer> {
        if let Some(rx_identifer) = self
            .translated_to_rx_identifier_map
            .get(&lookup_packet_metadata)
        {
            return Some(rx_identifer.clone());
        }

        None
    }

    /// Build new packet routable to client using real reply packet metadata and lookup packet
    /// Lookup packet metadata is a translated metadata which is stored while creating new route
    /// for first time.
    pub fn build_packet_from_translated_packet_metadata(
        &self,
        reply_packet_metadata: &PacketMetadata,
        lookup_packet_metadata: &PacketMetadata,
        reply_packet: &[u8],
    ) -> NatResult<Vec<u8>> {
        let original_packet_metadata =
            match self.translated_to_original_map.get(&lookup_packet_metadata) {
                Some(metadata) => metadata,
                None => {
                    let error_message = "Original packet metadata could not be found. Perhaps,
                    mapping entry is already removed."
                        .to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

        // Update NAT last activity
        self.update_last_activity(&original_packet_metadata);

        let mut delivery_response_packet_metadata = reply_packet_metadata.clone();
        delivery_response_packet_metadata.destination_address =
            original_packet_metadata.source_address;
        delivery_response_packet_metadata.destination_port = original_packet_metadata.source_port;

        let mut ip_packet = reply_packet.to_vec();
        let packet_payload;

        if lookup_packet_metadata.source_address.is_ipv4() {
            let mut mutable_ipv4_packet = match MutableIpv4Packet::new(&mut ip_packet) {
                Some(packet) => packet,
                None => {
                    let error_message =
                        "Invalid IPV4 reply packet received. Could not parse it.".to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

            Self::routable_ipv4_packet(
                &delivery_response_packet_metadata,
                &mut mutable_ipv4_packet,
            )?;

            let ihl = mutable_ipv4_packet.get_header_length();
            let ipv4_header_length = ihl * 4;
            packet_payload = &mut ip_packet[ipv4_header_length as usize..];
        } else if lookup_packet_metadata.source_address.is_ipv6() {
            let mut mutable_ipv6_packet = match MutableIpv6Packet::new(&mut ip_packet) {
                Some(packet) => packet,
                None => {
                    let error_message =
                        "Invalid IPV6 reply packet received. Could not parse it.".to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

            Self::routable_ipv6_packet(
                &delivery_response_packet_metadata,
                &mut mutable_ipv6_packet,
            )?;
            let ipv6_header_length = 40;
            packet_payload = &mut ip_packet[ipv6_header_length as usize..];
        } else {
            let error_message = "Unsupported packet version.".to_string();
            crate::logging::debug(&error_message);
            return Err(error_message);
        }

        if delivery_response_packet_metadata.protocol == Protocol::TCP {
            let mut mutable_tcp_packet = match MutableTcpPacket::new(packet_payload) {
                Some(packet) => packet,
                None => {
                    let error_message =
                        "Invalid TCP packet received to delivery client.".to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

            Self::routable_new_tcp_packet(
                &delivery_response_packet_metadata,
                &mut mutable_tcp_packet,
            )?;
        } else if delivery_response_packet_metadata.protocol == Protocol::UDP {
            let mut mutable_udp_packet = match MutableUdpPacket::new(packet_payload) {
                Some(packet) => packet,
                None => {
                    let error_message =
                        "Invalid UDP packet received to delivery client.".to_string();
                    crate::logging::debug(&error_message);
                    return Err(error_message);
                }
            };

            Self::routable_new_udp_packet(
                &delivery_response_packet_metadata,
                &mut mutable_udp_packet,
            )?;
        } else {
            let error_message = "Unsupported protocol version.".to_string();
            crate::logging::debug(&error_message);
            return Err(error_message);
        }

        Ok(ip_packet)
    }

    pub fn update_last_activity(&self, original_packet_metadata: &PacketMetadata) {
        if let Some(mut last_activity) = self
            .original_to_last_activity
            .get_mut(original_packet_metadata)
        {
            *last_activity = Instant::now();
        };
    }

    async fn clear_expired_mapping(&self, expiry_duration: &Duration, protocol: &Protocol) {
        let mut ticker = tokio::time::interval(*expiry_duration);

        loop {
            ticker.tick().await;
            let event_message = format!("Started periodic clean up for {:?}", protocol);
            crate::logging::debug(&event_message);

            let original_to_translated_mapping_len = self.original_to_translated_map.len();
            let translated_to_original_mapping_len = self.translated_to_original_map.len();

            if original_to_translated_mapping_len != translated_to_original_mapping_len {
                let info_message = "Translation maps are not of equal size. Might be latest record
                is missing.";
                crate::logging::debug(&info_message);
            }

            for mapping in self.original_to_last_activity.iter() {
                let original_metadata = mapping.key();
                let last_activity = mapping.value();

                if original_metadata.protocol != *protocol {
                    continue;
                }

                if last_activity.elapsed() > *expiry_duration {
                    let result = self.clear_mapping(Some(&original_metadata), None);
                    let error_message = format!(
                        "{:?} port original {:?} freed? {:}.",
                        protocol, original_metadata.source_port, result
                    );
                    crate::logging::debug(&error_message);
                }
            }
        }
    }

    async fn clear_expired_udp_mapping(self) {
        self.clear_expired_mapping(&self.config.udp_inactive_expiry_duration, &Protocol::UDP)
            .await;
    }

    async fn clear_expired_tcp_mapping(self) {
        self.clear_expired_mapping(&self.config.tcp_inactive_expiry_duration, &Protocol::TCP)
            .await;
    }

    pub async fn clear_mapping_periodic(&self) -> Vec<JoinHandle<()>> {
        let instance1 = self.clone();
        let instance2 = self.clone();

        let handler1 = tokio::spawn(async {
            crate::logging::debug(&"Spawning new task to free expired tcp ports.");
            Self::clear_expired_tcp_mapping(instance1).await;
        });

        let handler2 = tokio::spawn(async {
            crate::logging::debug(&"Spawning new task to free expired udp ports.");
            Self::clear_expired_udp_mapping(instance2).await;
        });

        vec![handler1, handler2]
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use pnet::packet::Packet;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::tcp;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::udp::UdpPacket;
    use uuid::Uuid;

    use crate::protocol::Protocol;

    use super::Nat;
    use super::NatConfig;

    fn build_ipv4_packet(
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        protocol: Protocol,
        payload: &[u8],
    ) -> Vec<u8> {
        let ip_header_length = 20;
        let data_offset;

        let next_header_protocol;
        match protocol {
            Protocol::TCP => {
                data_offset = 20;
                next_header_protocol = IpNextHeaderProtocols::Tcp;
            }

            Protocol::UDP => {
                data_offset = 8;
                next_header_protocol = IpNextHeaderProtocols::Udp;
            }
        }

        let payload_length = payload.len();
        let buffer_length = ip_header_length + data_offset + payload_length;

        let mut buffer = vec![0u8; buffer_length];

        // Build IP packet
        let mut ip_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(ip_header_length as u8 / 4);
        ip_packet.set_total_length(buffer_length as u16);
        ip_packet.set_next_level_protocol(next_header_protocol);
        ip_packet.set_source(source_address);
        ip_packet.set_destination(destination_address);
        ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

        if protocol == Protocol::TCP {
            // Build TCP packet
            let tcp_header_length = 20;
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[ip_header_length..]).unwrap();
            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(destination_port);
            tcp_packet.set_sequence(1);
            tcp_packet.set_acknowledgement(1);
            tcp_packet.set_data_offset(tcp_header_length / 4);
            tcp_packet.set_window(60000);
            tcp_packet.set_payload(payload);

            let checksum = tcp::ipv4_checksum(
                &tcp_packet.to_immutable(),
                &source_address,
                &destination_address,
            );
            tcp_packet.set_checksum(checksum);
        } else {
            println!("buff len: {}", buffer.len());
            println!("header len: {}", ip_header_length);
            let mut udp_packet = MutableUdpPacket::new(&mut buffer[ip_header_length..]).unwrap();
            udp_packet.set_source(source_port);
            udp_packet.set_destination(destination_port);
            udp_packet.set_payload(payload);
            udp_packet.set_length(payload.len() as u16);
            let checksum = udp::ipv4_checksum(
                &udp_packet.to_immutable(),
                &source_address,
                &destination_address,
            );
            udp_packet.set_checksum(checksum);
        }

        buffer
    }

    #[test]
    fn test_ipv4_tcp_routing() {
        let nat_config = NatConfig {
            source_ipv4: Ipv4Addr::new(10, 0, 0, 2),
            source_ipv6: None,
            udp_inactive_expiry_duration: Duration::from_secs(15),
            tcp_inactive_expiry_duration: Duration::from_secs(60),
        };
        let nat = Nat::with_config(nat_config.clone());

        let packet1_source_address = Ipv4Addr::new(127, 0, 0, 1);
        let packet1_destination_address = Ipv4Addr::new(1, 1, 1, 1);
        let packet1_tcp_source_port = 1234;
        let packet1_tcp_destination_port = 80;
        let packet1_tcp_payload = "Hello".as_bytes();

        let ip_packet1 = build_ipv4_packet(
            packet1_source_address,
            packet1_destination_address,
            packet1_tcp_source_port,
            packet1_tcp_destination_port,
            Protocol::TCP,
            &packet1_tcp_payload,
        );

        let rx_identifer = Uuid::new_v4();
        let routable_raw_packet1 = nat.route_target(&rx_identifer, &ip_packet1).unwrap();

        let routable_ip_packet1 = Ipv4Packet::new(&routable_raw_packet1).unwrap();
        // Validate source and destination addresses
        let routable_ip_packet1_source = routable_ip_packet1.get_source();
        let expected_routable_ip_packet1_source = nat_config.source_ipv4;
        assert_eq!(
            routable_ip_packet1_source,
            expected_routable_ip_packet1_source
        );
        assert_eq!(
            routable_ip_packet1.get_destination(),
            packet1_destination_address
        );

        // Validate source and destination port
        let routable_ipv4_payload1 = routable_ip_packet1.payload();
        let routable_ipv4_tcp_packet1 = TcpPacket::new(&routable_ipv4_payload1).unwrap();
        let expected_source_port = 1024; // Starts with 1024
        assert_eq!(routable_ipv4_tcp_packet1.get_source(), expected_source_port);

        // Validate payload
        let routable_ipv4_tcp_packet1_payload = routable_ipv4_tcp_packet1.payload();
        assert_eq!(routable_ipv4_tcp_packet1_payload, packet1_tcp_payload);

        // Simulate response packet
        let reply_routed_packet = build_ipv4_packet(
            packet1_destination_address,
            nat_config.source_ipv4,
            packet1_tcp_destination_port,
            1024,
            Protocol::TCP,
            &[],
        );

        let reply_packet_metadata = Nat::packet_metadata(&reply_routed_packet).unwrap();
        let lookup_key_metadata =
            Nat::translated_lookup_metadata_from_reply_packet_metadata(&reply_packet_metadata)
                .unwrap();
        let found_identifier = nat.lookup_rx_identifier(&lookup_key_metadata);
        assert_eq!(Some(rx_identifer), found_identifier);

        let routable_packet1_to_client = nat
            .build_packet_from_translated_packet_metadata(
                &reply_packet_metadata,
                &lookup_key_metadata,
                &reply_routed_packet,
            )
            .unwrap();

        let response_packet1 = Ipv4Packet::new(&routable_packet1_to_client).unwrap();
        assert_eq!(response_packet1.get_destination(), packet1_source_address);
        assert_eq!(response_packet1.get_source(), packet1_destination_address);

        // This packet is received by client
        let tcp_packet1_reply = TcpPacket::new(response_packet1.payload()).unwrap();
        assert_eq!(tcp_packet1_reply.get_source(), packet1_tcp_destination_port);
        assert_eq!(tcp_packet1_reply.get_destination(), packet1_tcp_source_port);
    }

    #[test]
    fn test_ipv4_udp_routing() {
        let nat_config = NatConfig {
            source_ipv4: Ipv4Addr::new(10, 0, 0, 2),
            source_ipv6: None,
            udp_inactive_expiry_duration: Duration::from_secs(15),
            tcp_inactive_expiry_duration: Duration::from_secs(60),
        };
        let nat = Nat::with_config(nat_config.clone());

        let packet_source_address = Ipv4Addr::new(127, 0, 0, 1);
        let packet_destination_address = Ipv4Addr::new(1, 1, 1, 1);
        let packet_udp_source_port = 1234;
        let packet_udp_destination_port = 53;
        let packet_udp_payload = b"Hello";

        let ip_packet = build_ipv4_packet(
            packet_source_address,
            packet_destination_address,
            packet_udp_source_port,
            packet_udp_destination_port,
            Protocol::UDP,
            packet_udp_payload,
        );

        let rx_identifier = Uuid::new_v4();
        let routable_raw_packet = nat.route_target(&rx_identifier, &ip_packet).unwrap();

        let routable_ip_packet = Ipv4Packet::new(&routable_raw_packet).unwrap();
        assert_eq!(routable_ip_packet.get_source(), nat_config.source_ipv4);
        assert_eq!(
            routable_ip_packet.get_destination(),
            packet_destination_address
        );

        let routable_payload = routable_ip_packet.payload();
        let routable_udp_packet = UdpPacket::new(routable_payload).unwrap();
        let expected_source_port = 1024;
        assert_eq!(routable_udp_packet.get_source(), expected_source_port);
        assert_eq!(
            routable_udp_packet.get_destination(),
            packet_udp_destination_port
        );
        assert_eq!(routable_udp_packet.payload(), packet_udp_payload);

        // Build reply from target server to NAT
        let reply_packet = build_ipv4_packet(
            packet_destination_address,
            nat_config.source_ipv4,
            packet_udp_destination_port,
            expected_source_port,
            Protocol::UDP,
            b"",
        );

        let reply_packet_metadata = Nat::packet_metadata(&reply_packet).unwrap();
        let lookup_key_metadata =
            Nat::translated_lookup_metadata_from_reply_packet_metadata(&reply_packet_metadata)
                .unwrap();
        let found_identifier = nat.lookup_rx_identifier(&lookup_key_metadata);
        assert_eq!(Some(rx_identifier), found_identifier);

        let reply_to_client = nat
            .build_packet_from_translated_packet_metadata(
                &reply_packet_metadata,
                &lookup_key_metadata,
                &reply_packet,
            )
            .unwrap();

        let response_ip_packet = Ipv4Packet::new(&reply_to_client).unwrap();
        assert_eq!(response_ip_packet.get_destination(), packet_source_address);
        assert_eq!(response_ip_packet.get_source(), packet_destination_address);

        let udp_reply_packet = UdpPacket::new(response_ip_packet.payload()).unwrap();
        assert_eq!(udp_reply_packet.get_source(), packet_udp_destination_port);
        assert_eq!(udp_reply_packet.get_destination(), packet_udp_source_port);
    }
}
