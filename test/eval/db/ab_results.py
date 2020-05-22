from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey
from sqlalchemy.orm import relationship

from eval.db.base import SQLBaseModel


class ABResults(SQLBaseModel):
    __tablename__ = 'ab_results'
    id = Column(Integer, primary_key=True)
    experience_id = Column(Integer, ForeignKey('short_tcp_ebpf_experiments.id'))

    client = Column(String, nullable=False)
    server = Column(String, nullable=False)
    timeout = Column(Float, nullable=False)  # in seconds

    cmd_client = Column(String)
    cmd_server = Column(String)

    raw_csv = Column(Text)

    ab_latency_cdf = relationship("ABLatencyCDF", backref="ab", lazy='dynamic')


class ABLatencyCDF(SQLBaseModel):
    __tablename__ = 'ab_latency_cdf'
    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey('ab_results.id'))

    percentage_served = Column(Float, nullable=False)
    time = Column(Float, nullable=False)  # in ms
