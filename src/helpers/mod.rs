use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, ipv4};
use pnet::packet::{tcp, udp};

use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;

pub fn validate_ipv4_packet(ip_packet: &[u8]) -> bool {
    let ip_packet = match Ipv4Packet::new(ip_packet) {
        Some(packet) => packet,
        None => {
            crate::logging::debug(format!(
                "Validation failed. Invalid packet {:?}.",
                ip_packet
            ));
            return false;
        }
    };

    let calculate_ip_packet_checksum = ipv4::checksum(&ip_packet);
    if ip_packet.get_checksum() != calculate_ip_packet_checksum {
        crate::logging::debug(format!(
            "Validation failed. Invalid packet {:?}.",
            ip_packet
        ));
        return false;
    }

    match ip_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let tcp_packet = match TcpPacket::new(ip_packet.payload()) {
                Some(packet) => packet,
                None => {
                    crate::logging::debug(format!(
                        "Invalid TCP checksum. Invalid packet {:?}.",
                        ip_packet
                    ));
                    return false;
                }
            };

            let calculated_tcp_checksum = tcp::ipv4_checksum(
                &tcp_packet,
                &ip_packet.get_source(),
                &ip_packet.get_destination(),
            );
            return tcp_packet.get_checksum() == calculated_tcp_checksum;
        }

        IpNextHeaderProtocols::Udp => {
            let udp_packet = match UdpPacket::new(ip_packet.payload()) {
                Some(packet) => packet,
                None => {
                    crate::logging::debug(format!(
                        "Invalid UDP checksum. Invalid packet {:?}.",
                        ip_packet
                    ));
                    return false;
                }
            };

            let calculated_udp_checksum = udp::ipv4_checksum(
                &udp_packet,
                &ip_packet.get_source(),
                &ip_packet.get_destination(),
            );
            return udp_packet.get_checksum() == calculated_udp_checksum;
        }

        _ => {
            crate::logging::debug(format!(
                "Validation failed. Unhandled protocol {:?}.",
                ip_packet
            ));
            return false;
        }
    }
}

pub fn validate_packet(ip_packet: &[u8]) -> bool {
    let version = ip_packet[0] >> 4;
    if version == 4 {
        return validate_ipv4_packet(ip_packet);
    }

    true
}

pub type TcpReadResult<T> = std::io::Result<T>;

pub trait TcpReader {
    fn read(&mut self, buffer: &mut [u8]) -> impl Future<Output = TcpReadResult<usize>>;
}

pub struct SimpleTcpReader {
    read_half: OwnedReadHalf,
}

impl SimpleTcpReader {
    pub fn new(read_half: OwnedReadHalf) -> Self {
        Self { read_half }
    }
}

impl TcpReader for SimpleTcpReader {
    fn read(&mut self, buffer: &mut [u8]) -> impl Future<Output = TcpReadResult<usize>> {
        async { self.read_half.read(buffer).await }
    }
}

pub struct FixedLengthBufferedReader {
    /// Growable buffer for reading data.
    main_buffer: Vec<u8>,
    /// Fixed size buffer for reading chunk.
    chunk_buffer: Vec<u8>,
    /// Store last read offset for shifting bytes.
    last_read_offset: usize,
    /// Store total buffer size for next read.
    main_buffer_size: usize,
}

impl FixedLengthBufferedReader {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            main_buffer: Vec::with_capacity(buffer_size),
            chunk_buffer: vec![0u8; buffer_size],
            last_read_offset: 0,
            main_buffer_size: 0,
        }
    }

    pub fn read(
        &mut self,
        n_bytes: usize,
        tcp_reader: &mut impl TcpReader,
    ) -> impl Future<Output = TcpReadResult<&[u8]>> {
        async move {
            // Some bytes might be refrenced as a read result before.
            // Remove those read bytes from the buffer memory.
            self.main_buffer.copy_within(self.last_read_offset.., 0);
            self.main_buffer
                .truncate(self.main_buffer_size - self.last_read_offset);

            // Untill main buffer has expected amount of bytes, fill the buffer.
            while self.main_buffer.len() < n_bytes {
                let chunk_buffer = self.chunk_buffer.as_mut_slice();
                let read_size = tcp_reader.read(chunk_buffer).await?;

                if read_size < 1 {
                    return Err(std::io::Error::other(format!(
                        "Read invalid bytes len: {}",
                        read_size
                    )));
                }

                let to_copy_chunk = &chunk_buffer[..read_size];
                self.main_buffer.extend_from_slice(to_copy_chunk);
            }

            let slice = &self.main_buffer[..n_bytes.clone()];
            self.main_buffer_size = self.main_buffer.len();
            self.last_read_offset = n_bytes;
            Ok(slice)
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::cmp::min;

    use crate::helpers::FixedLengthBufferedReader;

    use super::TcpReader;

    pub struct DummyTcpReader<'a> {
        data: &'a [u8],
        read_size: usize,
    }

    impl<'a> DummyTcpReader<'a> {
        pub fn new(data: &'a [u8]) -> Self {
            Self { data, read_size: 0 }
        }
    }

    impl<'a> TcpReader for DummyTcpReader<'a> {
        fn read(&mut self, buffer: &mut [u8]) -> impl Future<Output = super::TcpReadResult<usize>> {
            async {
                // This much bytes is readable.
                let remaining_read_bytes = self.data.len() - self.read_size;
                let write_size = min(remaining_read_bytes, buffer.len());
                if write_size == 0 {
                    return Err(std::io::Error::other(
                        "Read 0 bytes. Connection might be closed.",
                    ));
                }

                let dest_slice = &mut buffer[0..write_size];
                let new_read_slice = &self.data[self.read_size..self.read_size + write_size];
                dest_slice.copy_from_slice(new_read_slice);

                self.read_size += write_size;
                Ok(write_size)
            }
        }
    }

    #[tokio::test]
    async fn test_dummpy_tcp_reader() {
        let data = (0..100).collect::<Vec<u8>>();
        let mut dummy_tcp_reader = DummyTcpReader::new(&data);
        const BUFFER_SIZE: usize = 10;

        let read_times = data.len() / BUFFER_SIZE;
        let mut buffer = [0u8; BUFFER_SIZE];
        let extra_read_times = 2;
        let total_read_times = read_times + extra_read_times;

        for i in 0..total_read_times {
            let read_result = dummy_tcp_reader.read(&mut buffer).await;
            if i < read_times {
                let read_size = read_result.unwrap();
                assert_eq!(read_size, BUFFER_SIZE);
            } else {
                assert!(read_result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn test_fixed_length_buffered_reader() {
        let data = (0..100).collect::<Vec<u8>>();
        let mut dummy_tcp_reader = DummyTcpReader::new(&data);
        let mut buffered_reader = FixedLengthBufferedReader::new(10);

        let read_data1 = buffered_reader
            .read(2, &mut dummy_tcp_reader)
            .await
            .unwrap();
        assert_eq!(read_data1, (0..2).collect::<Vec<u8>>());

        let read_data2 = buffered_reader.read(98, &mut dummy_tcp_reader).await;
        assert_eq!(read_data2.unwrap(), (2..100).collect::<Vec<u8>>());

        // Try to read extra two bytes from the dummy tcp reader. Before this, all bytes are consumed.
        let read_data3 = buffered_reader.read(2, &mut dummy_tcp_reader).await;
        assert!(read_data3.is_err());
    }
}
