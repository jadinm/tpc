from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey
from sqlalchemy.orm import relationship

from eval.db.base import SQLBaseModel


class IPerfResults(SQLBaseModel):
    __tablename__ = 'iperf_results'
    id = Column(Integer, primary_key=True)
    experience_id = Column(Integer, ForeignKey('tcp_ebpf_experiments.id'))

    client = Column(String, nullable=False)
    server = Column(String, nullable=False)

    cmd_client = Column(String)
    cmd_server = Column(String)

    raw_json = Column(Text)

    connections = relationship("IPerfConnections", backref="iperf",
                               lazy='dynamic')


class IPerfConnections(SQLBaseModel):
    __tablename__ = 'iperf_connections'
    id = Column(Integer, primary_key=True)
    iperf_id = Column(Integer, ForeignKey('iperf_results.id'))

    connection_id = Column(Integer, nullable=False)

    start_samples = Column(Float)
    bw_samples = relationship("IPerfBandwidthSample",
                              backref="iperf_connection",
                              lazy='dynamic')
    max_volume = Column(Float)


class IPerfBandwidthSample(SQLBaseModel):
    __tablename__ = 'iperf_bandwidth_samples'
    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('iperf_connections.id'))

    time = Column(Float, nullable=False)
    bw = Column(Float, nullable=False)
