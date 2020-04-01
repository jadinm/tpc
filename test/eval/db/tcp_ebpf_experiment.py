from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float
from sqlalchemy.orm import relationship

from eval.db.base import SQLBaseModel
from eval.utils import INTERVALS


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

    def bw_sum_through_time(self):
        times = []
        bw = []
        bw_sum = {}

        bw_operations = []
        for iperf in self.iperfs:
            for connection in iperf.connections:
                for bw_sample in connection.bw_samples:
                    start = connection.start_samples + bw_sample.time \
                            - INTERVALS
                    end = connection.start_samples + bw_sample.time
                    bw_operations.append((start, bw_sample.bw))
                    bw_operations.append((end, -bw_sample.bw))

        bw_operations = sorted(bw_operations, key=lambda x: x[0])

        current_sum = bw_operations[0][1]
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

        return times, bw
