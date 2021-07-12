import numpy
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, \
    BigInteger
from sqlalchemy.orm import relationship

from eval.bpf_stats import Snapshot, FlowBenderSnapshot
from eval.db import IPerfConnections, IPerfResults, IPerfBandwidthSample
from eval.db.base import SQLBaseModel
from eval.utils import INTERVALS

# Cache (possible because we don't update these when we query them)
bw_sum_through_time = {}
bw_by_connection = {}


class TCPeBPFExperiment(SQLBaseModel):
    __tablename__ = 'tcp_ebpf_experiments'

    id = Column(Integer, primary_key=True)

    timestamp = Column(DateTime(timezone=True), nullable=False)

    valid = Column(Boolean, nullable=False, default=False)
    failed = Column(Boolean, nullable=False, default=True)

    # params

    topology = Column(String, nullable=False)  # path
    demands = Column(String, nullable=False)  # path
    ebpf = Column(Boolean, nullable=False)

    congestion_control = Column(String, nullable=False)
    gamma_value = Column(Float, nullable=False)
    random_strategy = Column(String, nullable=False)  # uniform, exp3, flowbender
    max_reward_factor = Column(Float, nullable=False)
    wait_before_initial_move = Column(BigInteger, nullable=False,
                                      default=1000000000)
    wait_unstable_rtt = Column(BigInteger, nullable=False, default=16)

    # tc changes
    monotonic_realtime_delta = Column(Float)  # time.time() - time.monotonic() at the time of run
    tc_changes = Column(String)  # json of the form [[sec_since_epoch, tc_command_1],...]

    # results

    iperfs = relationship("IPerfResults", backref="experiment",
                          lazy='dynamic')

    snapshots = relationship("SnapshotDBEntry", backref="experiment",
                             lazy='dynamic')

    def snap_class(self):
        return FlowBenderSnapshot \
            if self.random_strategy == "flowbender" or self.random_strategy == "flowbender_timer" else Snapshot

    def data_related_snapshots(self):
        """Filter out snapshots caused by iperf control connections"""
        filtered_snaps = []
        for s in self.snapshots.all():
            found = False
            for i in self.iperfs.all():
                for flow_tuple in i.flow_tuples():
                    found = len(flow_tuple) == 0 \
                            or self.snap_class().retrieve_from_hex(s.snapshot_hex).is_from_connection(flow_tuple)
                    if found:
                        break
                if found:
                    filtered_snaps.append(s)
                    break
        return filtered_snaps

    def snapshot_by_connection(self):
        snapshots = [self.snap_class().retrieve_from_hex(s.snapshot_hex) for s in self.data_related_snapshots()]
        snapshot_by_connection = {}
        for s in snapshots:
            snapshot_by_connection.setdefault(s.conn_key(), []).append(s)
        return snapshot_by_connection

    def bw_sum_through_time(self, db):
        times = []
        bw = []
        bw_sum = {}

        if bw_sum_through_time.get(self.id) is not None:
            return bw_sum_through_time[self.id]

        bw_operations = []
        for _, start_samples, time_sample, bw_sample in \
                db.query(IPerfResults, IPerfConnections.start_samples,
                         IPerfBandwidthSample.time, IPerfBandwidthSample.bw) \
                        .filter(self.id == IPerfResults.experience_id) \
                        .filter(IPerfResults.id == IPerfConnections.iperf_id) \
                        .filter(IPerfConnections.id
                                == IPerfBandwidthSample.connection_id) \
                        .all():
            start = start_samples + time_sample - INTERVALS
            end = start_samples + time_sample
            bw_operations.append((start, bw_sample))
            bw_operations.append((end, -bw_sample))

        bw_operations = sorted(bw_operations, key=lambda x: x[0])

        current_sum = 0
        for t, op in bw_operations:
            # Note that this already aggregates operations happening at the
            # same moment
            current_sum += op
            bw_sum[t] = current_sum

        bw_sum = [(t, b) for t, b in bw_sum.items()]
        bw_sum = sorted(bw_sum, key=lambda x: x[0])

        for t, b in bw_sum:
            times.append(t - bw_sum[0][0])
            bw.append(b)

        bw_sum_through_time[self.id] = times, bw
        return bw_sum_through_time[self.id]

    def bw_mean_sum(self, db, start=4, end=-1):
        """Compute the mean bandwidth of the network bandwidth used but
        ignoring the first 4 samples and the last one"""
        _, bw = self.bw_sum_through_time(db)
        bw = bw[start:end]
        if len(bw) > 0:
            return numpy.mean(bw)
        else:
            return 0

    def bw_by_connection(self, db, start=4, end=-1):
        """Compute the mean bandwidth for each connection used but
        ignoring the first 4 samples and the last one"""
        bws = []
        if bw_by_connection.get(self.id) is not None:
            return bw_by_connection[self.id]
        numpy.seterr('raise')  # Raise error when warning encountered
        for iperf in self.iperfs.all():
            bws_tmp = {}
            for conn_id, start_samples, bw_sample in \
                    db.query(IPerfConnections.id, IPerfBandwidthSample.time,
                             IPerfBandwidthSample.bw) \
                            .filter(iperf.id == IPerfConnections.iperf_id) \
                            .filter(IPerfConnections.id
                                    == IPerfBandwidthSample.connection_id) \
                            .all():
                bws_tmp.setdefault(conn_id, []).append((start_samples,
                                                        bw_sample))
            for value in bws_tmp.values():
                value.sort()
            bws.extend([numpy.mean([sample[1] for sample in samples][start:end])
                        for _, samples in bws_tmp.items()])
        bw_by_connection[self.id] = bws
        return bw_by_connection[self.id]

    def jain_fairness(self, db, start=4, end=-1):
        bw_data = self.bw_by_connection(db, start=start, end=end)

        if self.random_strategy == "uniform":
            if sum([b * b for b in bw_data]) == 0:
                print(self.id)
                print(self.topology)
                print(self.demands)
                print(self.valid)
                print(self.failed)
                print(bw_data)

        # https://en.wikipedia.org/wiki/Fairness_measure
        return sum(bw_data) * sum(bw_data) \
               / (len(bw_data) * sum([b * b for b in bw_data]))

    def stability_by_connection(self):
        snapshot_by_connection = self.snapshot_by_connection()

        nbr_changes_by_conn = {}
        exp3_last_prob_by_conn = {}  # To get how fast evolves the weights
        for k, v in snapshot_by_connection.items():
            v.sort()
            nbr_changes = -1  # The first path does not count as "change"
            last_idx = -1
            for snap in v:
                exp3_last_prob_by_conn.setdefault(k, []) \
                    .append((snap.time, snap.exp3_last_prob))
                if last_idx != snap.srh_id:
                    last_idx = snap.srh_id
                    nbr_changes += 1

            # The number of times that EXP3 did not move
            nbr_no_change = len(v) - nbr_changes

            nbr_changes_by_conn[k] = nbr_changes, nbr_no_change

        return nbr_changes_by_conn, exp3_last_prob_by_conn
