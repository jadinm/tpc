from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float
from sqlalchemy.orm import relationship

from eval.db.base import SQLBaseModel


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
    random_strategy = Column(String, nullable=False)

    # results

    iperfs = relationship("IPerfResults", backref="experiment",
                          lazy='dynamic')

    snapshots = relationship("SnapshotDBEntry", backref="experiment",
                             lazy='dynamic')
