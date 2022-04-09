import json

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

    connections = relationship("IPerfConnections", backref="iperf", lazy='selectin')

    def flow_tuples(self):
        """Returns the flow tuple for each connection (useful to remove noise snapshots of control connections)"""
        if self.raw_json is None:
            return []
        return json.loads(self.raw_json).get("start", {}).get("connected", [])


class IPerfConnections(SQLBaseModel):
    __tablename__ = 'iperf_connections'
    id = Column(Integer, primary_key=True)
    iperf_id = Column(Integer, ForeignKey('iperf_results.id'))

    connection_id = Column(Integer, nullable=False)

    start_samples = Column(Float)
    bw_samples = relationship("IPerfBandwidthSample", backref="iperf_connection", lazy='selectin')
    max_volume = Column(Float)

    def throughput_over_time(self):
        """in MB for the throughput, in seconds for the time and ordered"""
        bws = []
        start_sample = None
        for sample in self.bw_samples.order_by(IPerfBandwidthSample.time.asc()):
            if start_sample is None:
                start_sample = sample.time
            bws.append((sample.time - start_sample, sample.bw / 10 ** 3))
        return bws

class IPerfBandwidthSample(SQLBaseModel):
    __tablename__ = 'iperf_bandwidth_samples'
    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('iperf_connections.id'))

    time = Column(Float, nullable=False)
    bw = Column(Float, nullable=False)
