import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from eval.db.base import SQLBaseModel
from eval.db.iperf_results import IPerfResults, IPerfConnections, \
    IPerfBandwidthSample
from eval.db.snapshots import SnapshotDBEntry
from eval.db.tcp_ebpf_experiment import TCPeBPFExperiment

db_path = os.path.join(os.path.abspath(os.environ["HOME"]),
                       "srv6-rerouting.sqlite")


def get_connection() -> Session:
    engine = create_engine('sqlite:///{}'.format(db_path), echo=False)
    SQLBaseModel.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    return session


__all__ = ["IPerfResults", "IPerfResults", "IPerfConnections",
           "IPerfBandwidthSample", "TCPeBPFExperiment", "SnapshotDBEntry",
           "get_connection"]
