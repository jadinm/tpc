import json
import os
import shlex
import struct
import subprocess
from ipaddress import ip_address
from typing import List

from reroutemininet.config import SRLocalCtrl


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
                # TODO Remove print(str(snap))
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
