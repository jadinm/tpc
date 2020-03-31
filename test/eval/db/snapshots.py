from sqlalchemy import Column, Integer, String, Text, ForeignKey

from eval.db.base import SQLBaseModel


class SnapshotDBEntry(SQLBaseModel):
    __tablename__ = 'snapshots'
    id = Column(Integer, primary_key=True)
    experience_id = Column(Integer, ForeignKey('tcp_ebpf_experiments.id'))

    host = Column(String, nullable=False)
    snapshot_hex = Column(Text, nullable=False)
