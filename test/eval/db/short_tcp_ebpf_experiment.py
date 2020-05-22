from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, \
    BigInteger
from sqlalchemy.orm import relationship

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

