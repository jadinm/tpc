use std::fs::File;
use std::io::BufReader;
use pcarp::Capture;
use etherparse::{SlicedPacket, PacketHeaders, IpHeader, Ipv6Header, TcpHeader};
use etherparse::IpHeader::*;
use etherparse::TransportHeader::Tcp;
use serde::Serialize;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::alloc::System;
use std::ops::Add;
use std::cmp::max;
use std::str::FromStr;

const BULK_PORT: u16 = 80;
const INTERACTIVE_PORT: u16 = 8080;
const RESOLUTION: u32 = 250;

const NANOS_PER_MILLI: u32 = 1_000_000;

#[derive(PartialEq, Eq, Hash, Debug)]
struct TCPTuple {
    min_ip: [u8; 16],
    max_ip: [u8; 16],
    min_port: u16,
    max_port: u16,
}

impl TCPTuple {
    fn new(ip: &Ipv6Header, tcp: &TcpHeader) -> TCPTuple {
        TCPTuple { min_ip: ip.destination.min(ip.source), max_ip: ip.destination.max(ip.source), min_port: tcp.destination_port.min(tcp.source_port), max_port: tcp.destination_port.max(tcp.source_port) }
    }
}

#[derive(Serialize)]
struct ThroughputRecord {
    time_micro: u64,
    bytes_per_sec: u64,
}

#[derive(Serialize)]
struct LatencyRecord {
    time_micro: u64,
    request_duration_micro: u64,
}

#[derive(Serialize)]
struct Statistics {
    average: u64,
    median: u64,
    _90th_percentile: u64,
    _99th_percentile: u64,
    maximum_value: u64,
}

impl Statistics {
    fn compute(&mut self, values: &Vec<u64>) {
        self.median = *values.get(values.len() / 2).unwrap();
        self._90th_percentile = *values.get(values.len() * 90 / 100).unwrap();
        self._99th_percentile = *values.get(values.len() * 99 / 100).unwrap();
        self.maximum_value = *values.get(values.len() - 1).unwrap();
        self.average =values.iter().sum::<u64>() / values.len() as u64;
    }
}

#[derive(Serialize)]
struct StatisticsResults {
    //throughput: Statistics,
    latency: Statistics,
}

#[derive(Serialize)]
struct Results {
    //throughput: Vec<ThroughputRecord>,
    latency: Vec<LatencyRecord>,
    statistics: StatisticsResults
}

fn main() {
    let file = File::open(std::env::args().skip(1).next().expect("pcap file should be the first argument")
    ).expect("pcap file could not be opened");

    let start_offset = Duration::new(u64::from_str(&std::env::args().skip(2).next().expect("start offset (in seconds) should be the second argument")).expect("offset should be an unsigned integer"), 0);
    let end_offset = Duration::new(u64::from_str(&std::env::args().skip(3).next().expect("end offset (in seconds) should be the second argument")).expect("offset should be an unsigned integer"), 0);

    let mut pcap = Capture::new(file).unwrap();

    //let mut throughput: Vec<(SystemTime, u64)> = Vec::new();
    let resolution: Duration = Duration::new(0, RESOLUTION * NANOS_PER_MILLI);
    let mut reference_time: Option<SystemTime> = Option::None;
    let mut last_time: Option<SystemTime> = Option::None;
    let mut current_amount: u64 = 0;

    let mut latency: Vec<(SystemTime, Duration)> = Vec::new();
    let mut requests_sent: HashMap<TCPTuple, SystemTime> = HashMap::new();

    let mut start_time: SystemTime = SystemTime::UNIX_EPOCH;
    let mut end_time: SystemTime = SystemTime::UNIX_EPOCH;

    while let Some(pkt) = pcap.next() {
        if pkt.is_ok() {
            let pkt = pkt.unwrap();
            let pkt_time = pkt.timestamp.unwrap();

            if start_time == SystemTime::UNIX_EPOCH {
                start_time = pkt_time;
            }

            if start_time > pkt_time {
                // Since we work with the system clock, it could have been updated while capturing traffic
                start_time = pkt_time;
            }

            if pkt_time.duration_since(start_time).unwrap() < start_offset {
                continue
            }

            if pkt_time > end_time {
                end_time = pkt_time
            }
            match PacketHeaders::from_ethernet_slice(pkt.data) {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {
                    match value.ip {
                        None => {}
                        Some(Version4(_)) => panic!("IPv4 packets are not handled"),
                        Some(Version6(ip_hdr)) => {
                            match value.transport {
                                Some(Tcp(tcp_hdr)) => {
                                    match (tcp_hdr.source_port, tcp_hdr.destination_port) {
                                        /*(BULK_PORT, _) | (_, BULK_PORT) => {
                                             if reference_time.is_none() {
                                                reference_time = pkt.timestamp;
                                            }
                                            if last_time.is_none() {
                                                last_time = pkt.timestamp;
                                            }

                                            if last_time.is_some() && pkt_time.duration_since(last_time.unwrap()).unwrap() > resolution {
                                                 throughput.push((last_time.unwrap(), (current_amount as f64 * (Duration::new(1, 0).as_nanos() / resolution.as_nanos()) as f64) as u64));
                                                let mut distance = pkt_time.duration_since(reference_time.unwrap()).unwrap();
                                                distance -= Duration::from_nanos(distance.as_nanos() as u64 % resolution.as_nanos() as u64);
                                                last_time = reference_time.unwrap().checked_add(distance);
                                                current_amount = 0;
                                            }

                                            if last_time.is_some() && pkt_time.duration_since(last_time.unwrap()).unwrap() < resolution {
                                                current_amount += (ip_hdr.payload_length - tcp_hdr.header_len()) as u64;
                                            }
                                        }*/
                                        (_, INTERACTIVE_PORT) | (INTERACTIVE_PORT, _) => {
                                            if tcp_hdr.destination_port == INTERACTIVE_PORT &&
                                                tcp_hdr.syn {
                                                requests_sent.insert(TCPTuple::new(&ip_hdr, &tcp_hdr), pkt_time);
                                            }

                                            if tcp_hdr.source_port == INTERACTIVE_PORT &&
                                                tcp_hdr.fin {
                                                let k = &TCPTuple::new(&ip_hdr, &tcp_hdr);
                                                match requests_sent.get(k) {
                                                    None => {}
                                                    Some(request_time) => {
                                                        let d = pkt_time.duration_since(*request_time).unwrap();
                                                        if d < Duration::new(0, 2 * NANOS_PER_MILLI) {
                                                            println!("4Tuple: {:?}", k);
                                                            println!("IP: {:?}, TCP: {:?}", ip_hdr, tcp_hdr);
                                                            panic!("Duration {:?} seems unrealistic", d);
                                                        }
                                                        latency.push((pkt_time, d));
                                                        requests_sent.remove(k);
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    let mut results = Results { /*throughput: Vec::with_capacity(throughput.len()),*/ latency: Vec::with_capacity(latency.len()),
    statistics: StatisticsResults{
/*        throughput: Statistics {
            average: 0,
            median: 0,
            _90th_percentile: 0,
            _99th_percentile: 0,
            maximum_value: 0
        },*/
        latency: Statistics {
            average: 0,
            median: 0,
            _90th_percentile: 0,
            _99th_percentile: 0,
            maximum_value: 0
        }
    } };

    /*for t in throughput {
        if end_time.duration_since(t.0).unwrap() > end_offset {
            results.throughput.push(ThroughputRecord { time_micro: t.0.duration_since(UNIX_EPOCH).unwrap().as_micros() as u64, bytes_per_sec: t.1 });
        }
    }*/

    for l in latency {
        if end_time.duration_since(l.0).unwrap() > end_offset {
            results.latency.push(LatencyRecord { time_micro: l.0.duration_since(UNIX_EPOCH).unwrap().as_micros() as u64, request_duration_micro: l.1.as_micros() as u64 });
        }
    }

    let mut values: Vec<u64> = Vec::with_capacity(/*max(results.throughput.len(), */results.latency.len()/*)*/);
    /*for t in &results.throughput {
        values.push(t.bytes_per_sec);
    }
    values.sort();
    results.statistics.throughput.compute(&values);*/

    values.clear();
    for l in &results.latency {
        values.push(l.request_duration_micro);
    }
    values.sort();
    results.statistics.latency.compute(&values);

    match serde_json::to_string(&results) {
        Ok(json) => println!("{}", json),
        _ => {}
    }
}
