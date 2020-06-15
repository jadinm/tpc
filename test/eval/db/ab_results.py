from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey, \
    BigInteger
from sqlalchemy.orm import relationship

from eval.db.base import SQLBaseModel


class ABResults(SQLBaseModel):
    __tablename__ = 'ab_results'
    id = Column(Integer, primary_key=True)
    experience_id = Column(Integer, ForeignKey('short_tcp_ebpf_experiments.id'))

    client = Column(String, nullable=False)
    server = Column(String, nullable=False)
    timeout = Column(Float, nullable=False)  # in seconds
    volume = Column(BigInteger, nullable=False)  # in kB

    cmd_client = Column(String)
    cmd_server = Column(String)

    raw_csv = Column(Text)

    ab_latency_cdf = relationship("ABLatencyCDF", backref="ab", lazy='dynamic')
    ab_latency = relationship("ABLatency", backref="ab", lazy='dynamic')

    def latency_over_time(self):
        """in ms and ordered"""
        latencies = []
        start_sample = None
        for sample in self.ab_latency.order_by(ABLatency.timestamp.asc()):
            if start_sample is None:
                start_sample = sample.timestamp / 10**6
            latencies.append((sample.timestamp / 10**6 - start_sample,
                              sample.latency / 10**3))
        return latencies


class ABLatencyCDF(SQLBaseModel):
    __tablename__ = 'ab_latency_cdf'
    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('ab_results.id'))

    percentage_served = Column(Float, nullable=False)
    time = Column(Float, nullable=False)  # in ms


class ABLatency(SQLBaseModel):
    __tablename__ = 'ab_latency'
    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('ab_results.id'))

    timestamp = Column(Float, nullable=False)  # in µs
    latency = Column(Float, nullable=False)  # in µs
