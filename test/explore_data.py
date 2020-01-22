import json
import os

from eval.bpf_stats import Snapshot


def explore_bw_json_files(src_dir):
    bw_data = {}
    snapshots = {}
    bw_files = []
    for root, directories, files in os.walk(src_dir):
        if "logs-" not in root:
            continue
        for f in files:
            if ".json" in f and "repetita_" in f:
                bw_files.append(os.path.join(root, f))

    # Order files by date so that old data gets erased by newest experiments
    bw_files.sort()
    print(bw_files)

    # Get back the bandwidth data
    for f in bw_files:
        with open(f) as file_obj:
            data = json.load(file_obj)
            if "bw" not in data or "id" not in data:
                continue
            data_copy = [(int(k), float(v)) for k, v in data["bw"].items()]
            bw_data.setdefault(data["id"]["topo"], {}).setdefault(data["id"]["demands"], {})\
                .setdefault(data["id"]["maxseg"], {})[data["id"]["ebpf"]] = data_copy
            if "snapshots" not in data:
                continue
            snapshot_copy = {h: [Snapshot.retrieve_from_hex(s) for s in snaps]
                             for h, snaps in data["snapshots"].items()}
            snapshots.setdefault(data["id"]["topo"], {}).setdefault(data["id"]["demands"], {})\
                .setdefault(data["id"]["maxseg"], {})[data["id"]["ebpf"]] = snapshot_copy

    return bw_data, snapshots


def explore_maxflow_json_files(src_dir):
    maxflow_data = {}
    srmip_files = []
    for root, directories, files in os.walk(src_dir):
        for f in files:
            if "solution.json" in f:
                srmip_files.append(os.path.join(root, f))

    # Order files by date so that old data gets erased by newest experiments
    srmip_files.sort()

    # Get back the bandwidth data
    for f in srmip_files:
        with open(f) as file_obj:
            data = json.load(file_obj)
            if "id" not in data or "flows" not in data:
                continue
            for _, flow in data["flows"].items():
                for exp in flow:
                    if not exp["MPTCP"]:
                        maxflow_data.setdefault(os.path.basename(data["id"]["topo"]), {}) \
                            .setdefault(os.path.basename(data["id"]["demands"]), {})[exp["maxseg"]] \
                            = exp["data"]["Solution"]["objective value"]

    return maxflow_data
