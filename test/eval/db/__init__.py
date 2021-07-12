import os
import shutil

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from eval.db.ab_results import ABResults, ABLatencyCDF, ABLatency
from eval.db.base import SQLBaseModel
from eval.db.iperf_results import IPerfResults, IPerfConnections, \
    IPerfBandwidthSample
from eval.db.short_tcp_ebpf_experiment import ShortTCPeBPFExperiment
from eval.db.snapshots import SnapshotDBEntry, SnapshotShortDBEntry
from eval.db.tcp_ebpf_experiment import TCPeBPFExperiment

db_path = os.path.join(os.path.abspath(os.environ["HOME"]),
                       "srv6-rerouting.sqlite")


def get_connection(readonly=False) -> Session:
    if readonly:
        ramdisk_path = os.path.join("/tmp", os.path.basename(db_path))
        shutil.copy(db_path, ramdisk_path)
        engine = create_engine('sqlite:///{}'.format(ramdisk_path), echo=False)
    else:
        engine = create_engine('sqlite:///{}'.format(db_path), echo=False)
    SQLBaseModel.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    return session


__all__ = ["IPerfResults", "IPerfResults", "IPerfConnections",
           "IPerfBandwidthSample", "TCPeBPFExperiment", "SnapshotDBEntry",
           "get_connection", "ShortTCPeBPFExperiment", "ABLatencyCDF",
           "ABResults", "SnapshotShortDBEntry", "ABLatency"]
