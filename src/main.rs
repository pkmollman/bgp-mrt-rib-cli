use chrono::prelude::*;
use clap::{Parser, Subcommand};
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Parser, Debug)]
struct CLIArgs {
    mrt_rib: String,
}

struct CommonHeader {
    // common header format
    // 4 octets: timestamp
    // 2 octets: type
    // 2 octets: subtype
    // 4 octets: length
    timestamp: DateTime<Utc>,
    mrt_type: u16,
    mrt_subtype: u16,
    length: u32,
    payload: Vec<u8>,
}

enum MRTType {
    // 11   OSPFv2
    // 12   TABLE_DUMP
    // 13   TABLE_DUMP_V2
    // 16   BGP4MP
    // 17   BGP4MP_ET
    // 32   ISIS
    // 33   ISIS_ET
    // 48   OSPFv3
    // 49   OSPFv3_ET
    OSPFv2 = 11,
    TABLEDUMP = 12,
    TABLEDUMPV2 = 13,
    BGP4MP = 16,
    BGP4MPET = 17,
    ISIS = 32,
    ISISET = 33,
    OSPFv3 = 48,
    OSPFv3ET = 49,
}

struct TableDump {
    // 2 octets: view number
    // 2 octets: sequence number
    // 4 octets: prefix
    // 1 octet: prefix length
    // 1 octet: status
    // 4 octets: originated time
    // 4 octets: peer IP address
    // 2 octets: peer AS
    // 2 octets: attribute length
    // variable: attribute
    view_number: u16,
    sequence_number: u16,
    prefix: IpAddr,
    prefix_length: u8,
    status: u8,
    originated_time: DateTime<Utc>,
    peer_ip: IpAddr,
    peer_as: u16,
    attribute_length: u16,
    attribute: Vec<u8>,
}

struct TableDumpV2 {}

enum TableDumpV2Subtype {
    PEERINDEXTABLE = 1,
    RIBIPV4UNICAST = 2,
    RIBIPV4MULTICAST = 3,
    RIBIPV6UNICAST = 4,
    RIBIPV6MULTICAST = 5,
    RIBGENERIC = 6,
}

fn read_common_header(mrt_file: &mut std::fs::File) {
    let mut buf = [0; 4];
    mrt_file.read_exact(&mut buf).unwrap();
    let timestamp_i = u32::from_be_bytes(buf);
    // convert timestamp to a date string
    let timestamp = timestamp_i as u64;
    let date = chrono::DateTime::from_timestamp(timestamp as i64, 0).unwrap();
    let date_str = date.format("%Y-%m-%d %H:%M:%S").to_string();
    println!("Timestamp: {}", date_str);

    // next 2 octets are the type
    let mut buf = [0; 2];
    mrt_file.read_exact(&mut buf).unwrap();
    let type_i = u16::from_be_bytes(buf);

    // next 2 octets are the subtype
    let mut buf = [0; 2];
    mrt_file.read_exact(&mut buf).unwrap();
    let subtype_i = u16::from_be_bytes(buf);

    println!("type: {}", type_i);
    println!("subtype: {}", subtype_i);

    // next 4 octets are the length
    let mut buf = [0; 4];
    mrt_file.read_exact(&mut buf).unwrap();
    let length_i = u32::from_be_bytes(buf);
    println!("length: {}", length_i);

    // next length_i octets are the payload
    let mut buf = vec![0; length_i as usize];
    mrt_file.read_exact(&mut buf).unwrap();

    let common_header = CommonHeader {
        timestamp: date,
        mrt_type: type_i,
        mrt_subtype: subtype_i,
        length: length_i,
        payload: buf,
    };

    match common_header.mrt_type {
        13 => match common_header.mrt_subtype {
            1 => {
                let table_dump = PeerIndexTable::from_bytes(&common_header.payload);
                println!("Table Dump: {:?}", table_dump)
            }
            2 => {
                let rib_dump = RIBIPV4UNICAST::from_bytes(&common_header.payload);
                println!("Table Dump: {:?}", rib_dump)
            }
            _ => {
                panic!("Unknown subtype: {}", common_header.mrt_subtype)
            }
        },
        _ => {}
    }
}

#[derive(Debug)]
struct PeerIndexTable {
    collector_bgp_id: u32,
    view_name: Option<String>,
    peers: Vec<PeerEntry>,
}

impl PeerIndexTable {
    fn from_bytes(bytes: &[u8]) -> PeerIndexTable {
        let mut bytes = std::io::Cursor::new(bytes);
        // first 4 bytes are the collector BGP ID
        let mut collector_bgp_id = [0; 4];
        bytes.read_exact(&mut collector_bgp_id).unwrap();

        let collector_bgp_id = u32::from_be_bytes(collector_bgp_id);
        println!("Collector BGP ID: {}", collector_bgp_id);

        // next 2 bytes are the view name length
        let mut view_name_length_buffer = [0; 2];
        bytes.read_exact(&mut view_name_length_buffer).unwrap();

        let view_name_length = u16::from_be_bytes(view_name_length_buffer);

        let view_name = match view_name_length {
            0 => None,
            _ => {
                let mut view_name = vec![0; view_name_length as usize];
                bytes.read_exact(&mut view_name).unwrap();
                Some(String::from_utf8(view_name).unwrap())
            }
        };

        let mut peer_count_buffer = [0; 2];
        bytes.read_exact(&mut peer_count_buffer).unwrap();

        let peer_count = u16::from_be_bytes(peer_count_buffer);
        println!("Peer count: {}", peer_count);

        let mut peers: Vec<PeerEntry> = Vec::new();

        while peers.len() < peer_count as usize {
            // first byte is the peer type
            let mut peer_type = [0; 1];
            bytes.read_exact(&mut peer_type).unwrap();

            // println!("peer_type field: {}", peer_type[0]);

            let addr_type = peer_type[0] & 0b0000_0001;
            let asn_type = peer_type[0] & 0b0000_0010;

            // println!("addr type: {}", addr_type);
            // println!("asn type: {}", asn_type);

            // next 4 bytes are the BGP ID
            let mut bgp_id = [0; 4];
            bytes.read_exact(&mut bgp_id).unwrap();

            let addr: IpAddr = match addr_type {
                0 => {
                    // next 4 bytes are the address
                    let mut address = [0; 4];
                    bytes.read_exact(&mut address).unwrap();
                    Ipv4Addr::new(address[0], address[1], address[2], address[3]).into()
                }
                1 => {
                    // next 16 bytes are the address
                    let mut address = [0; 16];
                    bytes.read_exact(&mut address).unwrap();
                    Ipv6Addr::new(
                        u16::from_be_bytes([address[0], address[1]]),
                        u16::from_be_bytes([address[2], address[3]]),
                        u16::from_be_bytes([address[4], address[5]]),
                        u16::from_be_bytes([address[6], address[7]]),
                        u16::from_be_bytes([address[8], address[9]]),
                        u16::from_be_bytes([address[10], address[11]]),
                        u16::from_be_bytes([address[12], address[13]]),
                        u16::from_be_bytes([address[14], address[15]]),
                    )
                    .into()
                }
                _ => {
                    panic!("Invalid ADDR type");
                }
            };

            let asn: u32 = match asn_type {
                0 => {
                    // next 2 bytes are the ASN
                    let mut asn = [0; 2];
                    bytes.read_exact(&mut asn).unwrap();
                    u16::from_be_bytes(asn) as u32
                }
                2 => {
                    // next 4 bytes are the ASN
                    let mut asn = [0; 4];
                    bytes.read_exact(&mut asn).unwrap();
                    u32::from_be_bytes(asn)
                }
                _ => {
                    panic!("Invalid ASN type");
                }
            };

            peers.push(PeerEntry {
                bgp_id: u32::from_be_bytes(bgp_id),
                asn,
                address: addr,
            });

            println!("Peer: {:?}", peers.last().unwrap());
        }

        PeerIndexTable {
            collector_bgp_id,
            view_name,
            peers,
        }
    }
}

#[derive(Debug)]
struct PeerEntry {
    bgp_id: u32,
    asn: u32,
    address: IpAddr,
}

#[derive(Debug)]
struct RIBIPV4UNICAST {
    sequence_number: u32,
    prefix_length: u8,
    prefix: IpAddr,
    entry_count: u16,
    entries: Vec<RIBEntry>,
}

#[derive(Debug)]
struct RIBEntry {
    peer_index: u16,
    originated_time: u32,
    attribute_length: u16,
    attributes: Vec<RIBAttribute>,
}

#[derive(Debug)]
struct RIBAttribute {
    flags: u8,
    type_code: u8,
    length: u16,
    value: Vec<u8>,
}

impl RIBIPV4UNICAST {
    fn from_bytes(bytes: &[u8]) -> RIBIPV4UNICAST {
        let mut bytes = std::io::Cursor::new(bytes);

        let mut sequence_number_buffer = [0; 4];
        bytes.read_exact(&mut sequence_number_buffer).unwrap();
        let sequence_number = u32::from_be_bytes(sequence_number_buffer);

        println!("Sequence number: {}", sequence_number);

        let mut prefix_length_buffer = [0; 1];
        bytes.read_exact(&mut prefix_length_buffer).unwrap();
        let prefix_length = prefix_length_buffer[0];

        let prefix = match prefix_length {
            0 => Ipv4Addr::new(0, 0, 0, 0).into(),
            _ => {
                let prefix_octets = (prefix_length as f32 / 8.0).ceil() as usize;
                let mut prefix = vec![0; prefix_octets];
                bytes.read_exact(&mut prefix).unwrap();
                while prefix.len() < 4 {
                    prefix.push(0);
                }
                Ipv4Addr::new(prefix[0], prefix[1], prefix[2], prefix[3]).into()
            }
        };

        println!("Prefix {}/{}", prefix, prefix_length);

        let mut entry_count_buffer = [0; 2];
        bytes.read_exact(&mut entry_count_buffer).unwrap();
        let entry_count = u16::from_be_bytes(entry_count_buffer);

        println!("Entry count: {}", entry_count);
        println!("buffer size: {}", bytes.get_ref().len());

        let mut entries: Vec<RIBEntry> = Vec::new();

        while entries.len() < entry_count as usize {
            let mut peer_index_buffer = [0; 2];
            bytes.read_exact(&mut peer_index_buffer).unwrap();
            let peer_index = u16::from_be_bytes(peer_index_buffer);

            println!("Peer index: {}", peer_index);

            let mut originated_time_buffer = [0; 4];
            bytes.read_exact(&mut originated_time_buffer).unwrap();
            let originated_time = u32::from_be_bytes(originated_time_buffer);

            // get timestamp from originated_time
            let timestamp = chrono::DateTime::from_timestamp(originated_time as i64, 0).unwrap();
            let timestamp = timestamp.format("%Y-%m-%d %H:%M:%S").to_string();

            println!("Timestamp: {}", timestamp);

            let mut attribute_length_buffer = [0; 2];
            bytes.read_exact(&mut attribute_length_buffer).unwrap();
            let attribute_length = u16::from_be_bytes(attribute_length_buffer);

            println!("attribute_length: {}", attribute_length);

            let mut attributes: Vec<RIBAttribute> = Vec::new();

            // store the attribute bytes in a buffer
            let mut attribute_buffer = vec![0; attribute_length as usize];
            bytes.read_exact(&mut attribute_buffer).unwrap();

            let mut attribute_bytes = std::io::Cursor::new(attribute_buffer);

            while attribute_bytes.position() < attribute_length as u64 {
                let mut flags_buffer = [0; 1];
                attribute_bytes.read_exact(&mut flags_buffer).unwrap();
                let flags = flags_buffer[0];

                println!("flags: {:08b}", flags);
                let extended_length = flags & 0b0001_0000 != 0;

                println!("extended_length: {}", extended_length);

                let mut type_code_buffer = [0; 1];
                attribute_bytes.read_exact(&mut type_code_buffer).unwrap();
                let type_code = type_code_buffer[0];

                let length;

                if extended_length {
                    let mut length_buffer = [0; 2];
                    attribute_bytes.read_exact(&mut length_buffer).unwrap();
                    length = u16::from_be_bytes(length_buffer);
                } else {
                    let mut length_buffer = [0; 1];
                    attribute_bytes.read_exact(&mut length_buffer).unwrap();
                    length = length_buffer[0] as u16;
                }

                match type_code {
                    1 => {
                        let mut value = vec![0; length as usize];
                        attribute_bytes.read_exact(&mut value).unwrap();
                        println!("Origin: {:?}", value);
                    }
                    2 => {
                        let mut seg_type_buffer = [0; 1];
                        attribute_bytes.read_exact(&mut seg_type_buffer).unwrap();
                        let seg_type = seg_type_buffer[0];

                        println!("seg type: {}", seg_type);

                        let mut seg_length_buffer = [0; 1];
                        attribute_bytes.read_exact(&mut seg_length_buffer).unwrap();
                        let seg_length = seg_length_buffer[0];

                        println!("seg length: {}", seg_length);

                        for _ in 0..seg_length {
                            let mut value = [0; 4];
                            attribute_bytes.read_exact(&mut value).unwrap();
                            println!("AS Path: {:?}", u32::from_be_bytes(value));
                        }
                    }
                    3 => {
                        let mut value = [0; 4];
                        attribute_bytes.read_exact(&mut value).unwrap();
                        println!(
                            "Next Hop: {:?}",
                            Ipv4Addr::new(value[0], value[1], value[2], value[3]),
                        );
                    }
                    4 => {
                        let mut value = [0; 4];
                        attribute_bytes.read_exact(&mut value).unwrap();
                        println!("MED: {:?}", u32::from_be_bytes(value));
                    }
                    5 => {
                        let mut value = [0; 4];
                        attribute_bytes.read_exact(&mut value).unwrap();
                        println!("Local Preference: {:?}", u32::from_be_bytes(value));
                    }
                    6 => {
                        println!("ATOMIC_AGGREGATE");
                    }
                    7 => {
                        let mut agg_asn = [0; 4];
                        attribute_bytes.read_exact(&mut agg_asn).unwrap();

                        let mut agg_addr_buffer = [0; 4];
                        attribute_bytes.read_exact(&mut agg_addr_buffer).unwrap();

                        let agg_addr = Ipv4Addr::new(
                            agg_addr_buffer[0],
                            agg_addr_buffer[1],
                            agg_addr_buffer[2],
                            agg_addr_buffer[3],
                        );
                        println!(
                            "Aggregator: AS{:?} {}",
                            u32::from_be_bytes(agg_asn),
                            agg_addr
                        );
                    }
                    8 => {
                        for _ in 0..length / 4 {
                            let mut casn_buffer = [0; 2];
                            attribute_bytes.read_exact(&mut casn_buffer).unwrap();
                            let casn = u16::from_be_bytes(casn_buffer);

                            let mut community_buffer = [0; 2];
                            attribute_bytes.read_exact(&mut community_buffer).unwrap();
                            let community = u16::from_be_bytes(community_buffer);

                            println!("Community: {:?}:{:?}", casn, community);
                        }
                    }
                    32 => {
                        for _ in 0..length / 12 {
                            let mut ga_buffer = [0; 4];
                            attribute_bytes.read_exact(&mut ga_buffer).unwrap();
                            let ga_asn = u32::from_be_bytes(ga_buffer);

                            let mut ldp_1_buffer = [0; 4];
                            attribute_bytes.read_exact(&mut ldp_1_buffer).unwrap();
                            let ldp_1 = u32::from_be_bytes(ldp_1_buffer);

                            let mut ldp_2_buffer = [0; 4];
                            attribute_bytes.read_exact(&mut ldp_2_buffer).unwrap();
                            let ldp_2 = u32::from_be_bytes(ldp_2_buffer);

                            println!("Large Community: {:?}:{:?}:{:?}", ga_asn, ldp_1, ldp_2);
                        }
                    }
                    34 => {
                        let mut value = vec![0; length as usize];
                        println!("Local Pref: {:?}", value);
                    }
                    35 => {
                        let mut value = [0; 4];
                        attribute_bytes.read_exact(&mut value).unwrap();
                        let otc = u32::from_be_bytes(value);
                        println!("OTC: {}", otc);
                    }
                    _ => {
                        println!("Attribute: {:08b} {:?} {:?}", flags, type_code, length);
                        let mut value = vec![0; length as usize];
                        attribute_bytes.read_exact(&mut value).unwrap();
                        println!(
                            "Attribute: {:08b} {:?} {:?} {:?}",
                            flags, type_code, length, value
                        );
                        panic!("Unknown attribute type")
                    }
                }

                attributes.push(RIBAttribute {
                    flags,
                    type_code,
                    length,
                    value: Vec::new(),
                });
            }

            entries.push(RIBEntry {
                peer_index,
                originated_time,
                attribute_length,
                attributes,
            });
        }

        RIBIPV4UNICAST {
            sequence_number,
            prefix_length,
            prefix,
            entry_count,
            entries,
        }
    }
}

fn main() {
    let args = CLIArgs::parse();

    let mut file = std::fs::File::open(args.mrt_rib).unwrap();

    while true {
        read_common_header(&mut file);
    }
}
