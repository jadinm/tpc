from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, \
    BigInteger
from sqlalchemy.orm import relationship

from eval.bpf_stats import ShortSnapshot
from eval.db.base import SQLBaseModel

# Cache (possible because we don't update these when we query them)
bw_sum_through_time = {}
bw_by_connection = {}


class ShortTCPeBPFExperiment(SQLBaseModel):
    __tablename__ = 'short_tcp_ebpf_experiments'

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
    random_strategy = Column(String, nullable=False)
    max_reward_factor = Column(Float, nullable=False)
    wait_before_initial_move = Column(BigInteger, nullable=False,
                                      default=1000000000)

    # results

    abs = relationship("ABResults", backref="experiment", lazy='dynamic')

    snapshots = relationship("SnapshotShortDBEntry", backref="experiment",
                             lazy='dynamic')

    def stability_by_connection(self):
        snapshots = sorted([ShortSnapshot.retrieve_from_hex(s.snapshot_hex)
                            for s in self.snapshots.all()])

        nbr_changes_by_conn = {}
        srh_id_by_conn = {}  # To get how fast evolves the weights
        nbr_changes = -1  # The first path does not count as "change"
        last_idx = -1
        start = snapshots[0].time
        for snap in snapshots:
            srh_id_by_conn.setdefault(0, [])\
                .append(((snap.time - start) / 10**9, snap.last_srh_id_chosen))
            if last_idx != snap.last_srh_id_chosen:
                last_idx = snap.last_srh_id_chosen
                nbr_changes += 1

            # The number of times that EXP3 did not move
            nbr_no_change = len(snapshots) - nbr_changes

            nbr_changes_by_conn[0] = nbr_changes, nbr_no_change

        return nbr_changes_by_conn, srh_id_by_conn
