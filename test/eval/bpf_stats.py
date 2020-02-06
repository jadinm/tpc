import json
import os
import shlex
import struct
import subprocess
from ipaddress import ip_address, ip_interface, ip_network
from typing import List, Dict

from ipmininet.utils import L3Router

from reroutemininet.config import SRLocalCtrl
from reroutemininet.host import ReroutingHost
from reroutemininet.net import ReroutingNet

BPFTOOL = os.path.expanduser("~/ebpf_hhf/bpftool")

# struct floating_type {
# 	__u64 mantissa;
# 	__u32 exponent;
# } __attribute__((packed));
#
# struct flow_tuple {
# 	__u32 family;
# 	__u32 local_addr[4];
# 	__u32 remote_addr[4];
# 	__u32 local_port;
# 	__u32 remote_port;
# } __attribute__((packed));
#
# struct flow_infos {
# 	__u32 srh_id;
#	__u32 mss;
# 	__u32 last_reported_bw;
# 	__u64 sample_start_time;
# 	__u32 sample_start_bytes;
# 	__u64 last_move_time;
# 	__u64 wait_backoff_max; // current max wating time
# 	__u64 wait_before_move; // current waiting time
# 	__u64 first_loss_time;
# 	__u32 number_of_loss;
# 	__u64 rtt_count; // Count the number of RTT in the connection, this is useful to know if congestion signals are consecutive or not
# 	__u32 ecn_count; // Count the number of consecutive CWR sent (either from ECN or other causes)
# 	__u64 last_ecn_rtt; // The index of the last RTT were we sent an CWR
# 	__u32 exp3_last_number_actions;
# 	__u32 exp3_curr_reward;
# 	floating exp3_last_probability;
# 	__u64 exp3_weight_mantissa_0; // Current weight for each path
# 	__u32 exp3_weight_exponent_0;
# 	__u64 exp3_weight_mantissa_1; // Current weight for each path
# 	__u32 exp3_weight_exponent_1;
# 	__u64 exp3_weight_mantissa_2; // Current weight for each path
# 	__u32 exp3_weight_exponent_2;
# 	__u64 exp3_weight_mantissa_3; // Current weight for each path
# 	__u32 exp3_weight_exponent_3;
# } __attribute__((packed));
#
# struct flow_snapshot {
# 	__u32 sequence; // 0 if never used -> we change the lowest sequence id
# 	__u64 time;
# 	struct flow_tuple flow_id;
# 	struct flow_infos flow;
# } __attribute__((packed));


class Snapshot:

    def __init__(self, ebpf_map_entry):
        self.seq, self.time, _, src_1, src_2, dst_1, dst_2, self.src_port,\
            self.dst_port, self.srh_id, self.mss, self.last_reported_bw, \
            self.sample_start_time, self.sample_start_bytes, \
            self.last_move_time, self.wait_backoff_max, self.wait_before_move, \
            self.first_loss_time, self.number_of_loss, self.rtt_count,\
            self.ecn_count,  self.last_ecn_rtt, \
            self.exp3_last_number_actions, self.exp3_curr_reward, \
            exp3_last_probability_mantissa, exp3_last_probability_exponent, \
            exp3_weight_mantissa_0, exp3_weight_exponent_0, \
            exp3_weight_mantissa_1, exp3_weight_exponent_1, \
            exp3_weight_mantissa_2, exp3_weight_exponent_2,\
            exp3_weight_mantissa_3, exp3_weight_exponent_3 = \
            struct.unpack("<IQ"  # Start of flow_snapshot
                          + "I4q2I"  # flow id
                          + "3IQI4QIQIQ2I"  # flow info (except floats)
                          + "QIQIQIQIQI",  # Floats of flow info
                          ebpf_map_entry)
        self.ebpf_map_entry = ebpf_map_entry

        # Parse addresses
        self.src = ip_address(self.ebpf_map_entry[16:32])
        self.dst = ip_address(self.ebpf_map_entry[32:48])

        # Parse floats
        floatings = self.extract_floats([(exp3_last_probability_mantissa,
                                          exp3_last_probability_exponent),
                                         (exp3_weight_mantissa_0,
                                          exp3_weight_exponent_0),
                                         (exp3_weight_mantissa_1,
                                          exp3_weight_exponent_1),
                                         (exp3_weight_mantissa_2,
                                          exp3_weight_exponent_2),
                                         (exp3_weight_mantissa_3,
                                          exp3_weight_exponent_3)])
        self.exp3_last_prob = floatings[0]
        self.exp3_weights = floatings[1:]

    def __eq__(self, other):
        return self.seq == other.seq

    def conn_key(self):
        return str(self.src) + str(self.dst) + str(self.src_port) \
               + str(self.dst_port)

    def __lt__(self, other):
        return self.seq < other.seq

    @staticmethod
    def extract_floats(list_pair_floats) -> List[float]:
        decimals = []

        i = 0
        for mantissa, exponent in list_pair_floats:
            unbiased_exponent = exponent - 1024
            # The list of bits
            x = [(mantissa >> y) % 2 for y in range(64)]
            x.reverse()
            z = [(y * 2.0)**(unbiased_exponent - i)
                 for i, y in enumerate(x) if y != 0]
            decimals.append(sum(z))
            i += 1
        return decimals

    @classmethod
    def extract_info(cls, node):
        """Create the ordered list of valid snapshots taken a node"""

        # Find the LocalCtrl object to get the map id
        daemon = node.nconfig.daemon(SRLocalCtrl.NAME)
        if daemon.stat_map_id == -1:
            raise ValueError("Cannot find the id of the Stat eBPF map")

        cmd = "{bpftool} map -j dump id {map_id}"\
            .format(bpftool=BPFTOOL, map_id=daemon.stat_map_id)
        out = subprocess.check_output(shlex.split(cmd)).decode("utf-8")
        snapshots_raw = json.loads(out)

        snapshots = []
        for snap_raw in snapshots_raw:
            hex_str = "".join([byte_str[2:] for byte_str in snap_raw["value"]])
            snap = cls(ebpf_map_entry=bytes.fromhex(hex_str))
            if snap.seq > 0:  # Valid snapshot
                snapshots.append(snap)
        snapshots.sort()
        return snapshots

    def __str__(self):
        return "Snapshot<{seq}-{time}> for connection" \
               " {src}:{src_port} -> {dst}:{dst_port}: EXP3 weights {weights}" \
               " last prob {exp3_last_prob}" \
            .format(seq=self.seq, time=self.time, src=self.src,
                    src_port=self.src_port, dst=self.dst,
                    dst_port=self.dst_port, weights=self.exp3_weights,
                    exp3_last_prob=self.exp3_last_prob)

    def __hash__(self):
        return hash(self.seq)

    def export(self) -> str:
        return self.ebpf_map_entry.hex()

    @classmethod
    def retrieve_from_hex(cls, ebpf_map_entry: str):
        return cls(bytes.fromhex(ebpf_map_entry))


# struct dst_infos {
# 	struct ip6_addr_t dest;
# 	__u32 max_reward;
# 	struct srh_record_t srhs[4];
# } __attribute__((packed));
#
# struct ip6_addr_t {
# 	unsigned long long hi;
# 	unsigned long long lo;
# } __attribute__((packed));
#
# struct srh_record_t {
# 	__u32 srh_id;
# 	__u32 is_valid;
# 	__u64 curr_bw; // Mbps
# 	__u64 delay; // ms
# 	struct ip6_srh_t srh;
# } __attribute__((packed));
#
# struct ip6_srh_t {
# 	unsigned char nexthdr;
# 	unsigned char hdrlen;
# 	unsigned char type;
# 	unsigned char segments_left;
# 	unsigned char first_segment;
# 	unsigned char flags;
# 	unsigned short tag;
#
# 	struct ip6_addr_t segments[MAX_SEGMENTS_BY_SRH];
# } __attribute__((packed));


class BPFPaths:
    MAX_PATHS_BY_DEST = 4
    MAX_SEGMENTS_BY_SRH = 10

    def __init__(self, net: ReroutingNet, node: ReroutingHost, byte_chains):
        self.src = node.name
        self.byte_chains = byte_chains
        self.paths_by_dest = {}

        for chain in self.byte_chains:
            # Get destination
            dest_ip = ip_network(str(ip_address(chain[0:16])) + "/48")
            dest = None
            for key, value in net._ip_allocs.items():
                # We only want destinations with hosts
                if not L3Router.is_l3router_intf(value.intf()) \
                        and ip_address(key.split("/")[0]) in dest_ip:
                    dest = net.node_for_ip(key)
            if dest is None:  # Cannot translate
                continue
            self.paths_by_dest[dest.name] = []

            # Get SRH paths
            print(chain)
            chain = chain[20:]  # Remove key + max_reward
            srh_fixed_size = (8 + self.MAX_SEGMENTS_BY_SRH * 16)
            for i in range(self.MAX_PATHS_BY_DEST):
                chain = chain[24:]  # Remove srh_record data
                # Get SRH length
                print(i)
                print(chain)
                srh_len, srh_type = struct.unpack("BB", chain[1:3])
                if srh_type == 0:  # Unused or invalid SRH slot
                    chain = chain[srh_fixed_size:]  # Pass to next SRH
                    continue
                assert srh_len % 2 == 0, "Problem the srh_len cannot be " \
                                         "divided by 2"
                # Get the actual path
                path = []
                for j in range(srh_len // 2):
                    segment_idx = 8 + j * 16
                    segment_ip = ip_address(chain[segment_idx:segment_idx+16])
                    if "::" == str(segment_ip):
                        segment_router = "::"
                    else:
                        segment_router = net.node_for_ip(segment_ip).name
                    path.append(segment_router)
                path.reverse()
                self.paths_by_dest[dest.name].append(path)

                # Pass to next SRH record
                chain = chain[srh_fixed_size:]

    def __str__(self):
        paths_by_dest = json.dumps(self.paths_by_dest, indent=4)
        return "BPFPaths<{src}>\n{paths_by_dest}" \
            .format(src=self.src, paths_by_dest=paths_by_dest)

    def export(self) -> Dict:
        return {
            "src": self.src,
            "destinations": self.paths_by_dest
        }

    @classmethod
    def extract_info(cls, net: ReroutingNet, node: ReroutingHost):
        """Create the ordered list of valid snapshots taken a node"""

        # Find the LocalCtrl object to get the map id
        daemon = node.nconfig.daemon(SRLocalCtrl.NAME)
        if daemon.dest_map_id == -1:
            raise ValueError("Cannot find the id of the dest eBPF map")
        print(daemon.dest_map_id)

        cmd = "{bpftool} map -j dump id {map_id}"\
            .format(bpftool=BPFTOOL, map_id=daemon.dest_map_id)
        out = subprocess.check_output(shlex.split(cmd)).decode("utf-8")
        ebpf_map_entries = json.loads(out)
        ebpf_map_entries = ["".join([byte_str[2:]
                                     for byte_str in map_raw["value"]])
                            for map_raw in ebpf_map_entries]
        return cls(net, node, [bytes.fromhex(entry)
                               for entry in ebpf_map_entries])
