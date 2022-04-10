import copy
import csv
import json
import os
import signal
import subprocess
import time
from datetime import datetime
from shlex import split
from typing import List

from ipmininet.tests.utils import assert_connectivity

from examples.repetita_network import RepetitaTopo
from reroutemininet.clean import cleanup
from reroutemininet.config import Lighttpd, SRLocalCtrl
from reroutemininet.net import ReroutingNet
from .bpf_stats import Snapshot, BPFPaths, ShortSnapshot, FlowBenderSnapshot
from .db import get_connection, TCPeBPFExperiment, IPerfResults, \
    IPerfConnections, SnapshotShortDBEntry, ABLatencyCDF, ABResults, \
    ABLatency, ShortTCPeBPFExperiment, IPerfBandwidthSample, SnapshotDBEntry
from .utils import get_addr, MEASUREMENT_TIME, INTERVALS, TEST_DIR, FLOWBENDER_MEASUREMENT_TIME, \
    LOAD_BALANCER_MEASUREMENT_TIME, TRACEROUTE_MEASUREMENT_TIME


# LINK_BANDWIDTH = 100


def get_current_congestion_control():
    out = subprocess.check_output(["sysctl",
                                   "net.ipv4.tcp_congestion_control"],
                                  universal_newlines=True)
    return out.split(" = ")[-1][:-1]


def get_current_parameter(parameter_name):
    param_value = None
    with open(os.path.join(os.environ["TPC_EBPF"], "param.h")) as fileobj:
        for line in fileobj.readlines():
            phrase = "#define {} ".format(parameter_name)
            if phrase == line[:len(phrase)]:  # Thus commented lines are removed
                param_value = line.split(" ".format(parameter_name))[-1]
    if param_value is None:
        raise ValueError("Cannot find the {} value", param_value)
    return param_value


def get_current_gamma():
    return float(get_current_parameter("GAMMA(x)"))


def get_current_rand_type():
    return "exp3" if int(get_current_parameter("USE_EXP3")) == 1 else "uniform"


def get_current_max_reward_factor():
    return float(get_current_parameter("MAX_REWARD_FACTOR"))


def get_wait_before_initial_move():
    return int(get_current_parameter("WAIT_BEFORE_INITIAL_MOVE"))


def get_wait_unstable_rtt():
    return int(get_current_parameter("WAIT_UNSTABLE_RTT"))


def launch_iperf(lg, net, clients, servers, result_files, nbr_flows, clamp,
                 iperfs_db, ebpf=True, measurement_time=MEASUREMENT_TIME,
                 client_program=None, server_program=None):
    """
    :param net: The Network object
    :param clients: The list of client node names
    :param servers: The list of server node names
     (same size as the client list and it means that clients[i] will have a connection to servers[i])
    :param result_files: The list of file object where to store the output
     (same size as the client list and it means that clients[i] will have its output written to result_files[i])
    :param nbr_flows: The number of connections for each client server pair
    :param ebpf: Whether there is eBPF and ccgroup activated
    :return: a tuple <list of popen objects of servers, list of popen objects of clients>
    """
    try:
        subprocess.check_call(split("pkill iperf3"))
    except subprocess.CalledProcessError:
        pass

    pid_servers = []
    ports = [5201 + i for i in range(len(servers))]
    for i, server in enumerate(servers):
        cmd = "iperf3 -s -J -p %d --one-off" % ports[i]
        # 2>&1 > log_%s.log &"
        iperfs_db[i].cmd_server = cmd
        print("%s %s" % (server, cmd))
        if ebpf:
            pid_servers.append(net[server].run_cgroup(cmd, stdout=result_files[i], program=server_program))
        else:
            pid_servers.append(net[server].popen(cmd, stdout=result_files[i]))
    time.sleep(15)

    for pid in pid_servers:
        if pid.poll() is not None:
            lg.error("The server exited too early with err=%s\n" % pid.poll())
            for pid in pid_servers:
                if pid.poll() is None:
                    pid.kill()
            return [], []

    # Wait for connectivity
    assert_connectivity(net, v6=True)
    time.sleep(1)
    assert_connectivity(net, v6=True)

    pid_clients = []
    for i, client in enumerate(clients):
        cmd = "iperf3 -J -P {nbr_connections} -c {server_ip}" \
              " -t {duration} " \
              "-B {client_ip} -i {intervals} -p {port} -b {clamp}M" \
            .format(server_ip=get_addr(net[servers[i]]),
                    client_ip=get_addr(net[client]),
                    nbr_connections=nbr_flows[i], duration=measurement_time,
                    intervals=INTERVALS, port=ports[i], clamp=clamp[i])
        print("%s %s" % (client, cmd))
        iperfs_db[i].cmd_client = cmd
        if ebpf:
            pid_clients.append(
                net[client].run_cgroup(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       program=client_program))
        else:
            pid_clients.append(net[client].popen(split(cmd),
                                                 stderr=subprocess.DEVNULL,
                                                 stdout=subprocess.DEVNULL))
    time.sleep(5)

    for pid in pid_clients:
        if pid.poll() is not None:
            lg.error("The client exited too early with err=%s\n" % pid.poll())
            for pid in pid_clients + pid_servers:
                if pid.poll() is None:
                    pid.kill()
            return [], []

    time.sleep(10)  # TODO Should be replaced by a check on the netstate to check that connections are established

    return pid_servers, pid_clients


def parse_demands(json_demands):
    """Fuse demands with the same destination, source and volume"""

    merged_demands = {}
    for demand in json_demands:
        demand.setdefault("number", 1)
        str_key = "%s-%s-%s" % (demand["src"], demand["dest"], demand["volume"])
        if str_key in merged_demands:
            merged_demands[str_key]["number"] += demand["number"]
        else:
            merged_demands[str_key] = demand

    return [x for x in merged_demands.values()]


def get_repetita_topos(args):
    topos = {}
    if args.repetita_topo is None and args.repetita_dir is None:
        return
    if args.repetita_dir is not None:
        for root, directories, files in os.walk(args.repetita_dir):
            for f in files:
                if ".graph" in f:
                    # Identify related flow files
                    for flow_name in files:
                        if ".flows" in flow_name and f.split(".")[0] \
                                in flow_name:
                            topos.setdefault(os.path.join(root, f), []).append(
                                os.path.join(root, flow_name))

    if args.repetita_topo is not None:
        repetita_topo = os.path.abspath(args.repetita_topo)
        topo_name = os.path.basename(args.repetita_topo)
        print(args.repetita_topo)

        if args.repetita_demand is None:
            # Demands are to be derived from the topo name
            for root, directories, files in os.walk(os.path.dirname(repetita_topo)):
                for f in files:
                    if ".flows" in f and topo_name.split(".graph")[0] in f:
                        topos.setdefault(repetita_topo, []).append(os.path.join(root, f))
        else:
            # Allow to specify both topo AND demand
            topos.setdefault(repetita_topo, []).append(args.repetita_demand)
    return topos


def launch_ab(lg, net, clients, servers, nbr_flows, db_entry, csv_files,
              ebpf=True, measurement_time=MEASUREMENT_TIME) -> List[subprocess.Popen]:
    try:
        subprocess.check_call(split("pkill iperf3"))
        subprocess.check_call(split("pkill ab"))
    except subprocess.CalledProcessError:
        pass

    # Wait for connectivity
    assert_connectivity(net, v6=True)
    time.sleep(1)
    assert_connectivity(net, v6=True)

    time.sleep(30)

    pid_clients = []
    for i, client in enumerate(clients):
        cmd = "ab -v 0 -c {nbr_connections} -t {duration} -e {csv_file} " \
              "http://[{server_ip}]:8080/mock_file" \
            .format(server_ip=get_addr(net[servers[i]]), csv_file=csv_files[i],
                    nbr_connections=nbr_flows[i], duration=measurement_time)
        db_entry[i].cmd_client = cmd
        print(client)
        print(cmd)
        # Always run outside of the eBPF (use case where we only control
        # servers)
        pid_clients.append(net[client].popen(split(cmd)))

    return pid_clients


def trace_analysis(db_entry: ABResults, cwd: str):
    path = os.path.join(TEST_DIR, "report_throughput_latency/target/"
                                  "debug/report_throughput_latency")
    env = os.environ.copy()
    env["RUST_BACKTRACE"] = "full"
    out = subprocess.check_output(split("{} {}.pcapng 0 0"
                                        .format(path, db_entry.client)),
                                  universal_newlines=True, cwd=cwd, env=env)
    print("pcap analysis")
    data = json.loads(out)["latency"]
    print(data)
    for conn_data in data:
        db_entry.ab_latency.append(
            ABLatency(timestamp=conn_data["time_micro"],
                      latency=conn_data["request_duration_micro"]))


def parse_ab_output(csv_files, db_entry: List[ABResults], cwd: str):
    for i, cvs_file in enumerate(csv_files):
        with open(cvs_file) as file_obj:
            raw_data = file_obj.read()
            db_entry[i].raw_csv = raw_data
            latency = db_entry[i].ab_latency_cdf

            for j, row in enumerate(csv.DictReader(raw_data.splitlines())):
                if j == 0:  # Skip headline
                    continue
                print(row)
                # Insert in database
                latency.append(
                    ABLatencyCDF(
                        percentage_served=float(row["Percentage served"]),
                        time=float(row["Time in ms"])))
            trace_analysis(db_entry[i], cwd=cwd)


def get_xp_params():
    return {
        "congestion_control": get_current_congestion_control(),
        "gamma_value": get_current_gamma(),
        "random_strategy": get_current_rand_type(),
        "max_reward_factor": get_current_max_reward_factor(),
        "wait_before_initial_move": get_wait_before_initial_move(),
        "wait_unstable_rtt": get_wait_unstable_rtt()
    }


def short_flows_completion(lg, args, ovsschema):
    short_flows(lg, args, ovsschema, completion_ebpf=True)


def apply_changes(seconds_since_start: float, net: ReroutingNet):
    for change in net.topo.pending_changes:
        if change.time <= seconds_since_start:
            change.apply(net)
            print("CHANGE APPLIED: {}".format(change))
            net.topo.applied_changes.append(change)

    net.topo.pending_changes = \
        sorted(list(filter(lambda x: x not in net.topo.applied_changes,
                           net.topo.pending_changes)))

    # if len(applied_changes) >= 1:
    #     IPCLI(net)  # TODO Remove


def revert_changes(net: ReroutingNet):
    for change in net.topo.applied_changes:
        change.revert(net)

    if len(net.topo.applied_changes) > 0:
        time.sleep(5)


def short_flows(lg, args, ovsschema, completion_ebpf=False):
    topos = get_repetita_topos(args)
    os.mkdir(args.log_dir)

    lg.info("******* %d Topologies to test *******\n" % len(topos))
    db = get_connection()
    params = get_xp_params()
    subprocess.check_call(split("cargo build"),
                          cwd=os.path.join(TEST_DIR,
                                           "report_throughput_latency"))

    i = 0
    for topo, demands_list in topos.items():
        i += 1
        lg.info("******* [topo %d/%d] %d flow files to test in topo '%s' "
                "*******\n"
                % (i, len(topos), len(demands_list), os.path.basename(topo)))
        for demands in demands_list:
            cwd = os.path.join(args.log_dir, os.path.basename(topo) + '_' +
                               os.path.basename(demands))
            try:
                os.makedirs(cwd)
            except OSError as e:
                print("OSError %s" % e)
            cleanup()
            lg.info("******* Processing topo '%s' demands '%s' *******\n" % (
                os.path.basename(topo),
                os.path.basename(demands)))

            tcp_ebpf_experiment = \
                ShortTCPeBPFExperiment(timestamp=datetime.now(), topology=topo,
                                       demands=demands, ebpf=args.ebpf,
                                       completion_ebpf=completion_ebpf,
                                       **params)
            db.add(tcp_ebpf_experiment)

            with open(demands) as fileobj:
                json_demands = json.load(fileobj)
            topo_args = {"schema_tables": ovsschema["tables"], "cwd": cwd,
                         "always_redirect": True,
                         "maxseg": -1, "repetita_graph": topo,
                         "ebpf": args.ebpf,
                         "json_demands": json_demands,
                         "localctrl_opts": {
                             "short_ebpf_program":
                                 SRLocalCtrl.EXP3_LOWEST_COMPLETION_EBPF_PROGRAM
                                 if completion_ebpf
                                 else SRLocalCtrl.EXP3_LOWEST_DELAY_EBPF_PROGRAM
                         }}

            net = ReroutingNet(topo=RepetitaTopo(**topo_args),
                               static_routing=True)

            subprocess.call("pkill -9 iperf".split(" "))
            subprocess.call("pkill -9 curl".split(" "))
            subprocess.call("pkill -9 ab".split(" "))
            err = False
            csv_files = []
            tcpdumps = []
            measurement_time = net.topo.stopping_time if net.topo.stopping_time > 0 else MEASUREMENT_TIME
            try:
                net.start()

                # Read flow file to retrieve the clients and servers
                json_demands = parse_demands(json_demands)
                print(json_demands)
                clients = []
                servers = []
                nbr_flows = []
                flow_sizes = []
                for d in json_demands:
                    clients.append("h" + net.topo.getFromIndex(d["src"]))
                    servers.append("h" + net.topo.getFromIndex(d["dest"]))
                    nbr_flows.append(d["number"])
                    csv_files.append("%s-%s" % (clients[-1], servers[-1]))
                    flow_sizes.append(d["volume"])  # kB
                    tcp_ebpf_experiment.abs.append(
                        ABResults(client=clients[-1], server=servers[-1],
                                  timeout=measurement_time,
                                  volume=flow_sizes[-1]))
                    # Change size of served file
                    path = os.path.join(
                        net[servers[-1]].nconfig.daemon(
                            Lighttpd).options.web_dir,
                        "mock_file")
                    with open(path, "w") as fileobj:
                        fileobj.write("0" * (flow_sizes[-1] * 1000))
                    print(path)
                print(clients)
                print(servers)
                print(nbr_flows)

                # IPCLI(net)  # TODO Remove

                # Launch tcpdump on client
                tcpdump_hosts = copy.deepcopy(clients)
                pcap_files = []
                if args.tcpdump:
                    tcpdump_hosts += servers + [r.name for r in net.routers]
                for n in tcpdump_hosts:
                    pcap_file = os.path.join(cwd, n) + ".pcapng"
                    cmd = "tshark -F pcapng -w {} ip6".format(pcap_file)
                    pcap_files.append(pcap_file)
                    tcpdumps.append(net[n].popen(cmd))

                pid_abs = launch_ab(lg, net, clients, servers, nbr_flows,
                                    db_entry=tcp_ebpf_experiment.abs,
                                    csv_files=csv_files, ebpf=args.ebpf,
                                    measurement_time=measurement_time)
                if len(pid_abs) == 0:
                    return

                # IPCLI(net)  # TODO Remove

                # Measure load on each interface
                start_time = time.time()
                snapshots = {h: [] for h in clients + servers}
                while time.time() - start_time < measurement_time:
                    # Extract snapshot info from eBPF
                    if args.ebpf:
                        for h in snapshots.keys():
                            snapshots[h].extend(
                                ShortSnapshot.extract_info(net[h]))
                            snapshots[h] = sorted(list(set(snapshots[h])))
                    # Apply changes to the network if any
                    apply_changes(time.time() - start_time, net)
                    time.sleep(0.1)

                # IPCLI(net)  # TODO Remove
                time.sleep(5)

                for h, snaps in snapshots.items():
                    for snap in snaps:
                        tcp_ebpf_experiment.snapshots.append(
                            SnapshotShortDBEntry(snapshot_hex=snap.export(),
                                                 host=h)
                        )

                for i, pid in enumerate(pid_abs):
                    if pid.poll() is None:
                        lg.error("The ab (%s,%s) has not finish yet\n" % (
                            clients[i], servers[i]))
                        pid.send_signal(signal.SIGINT)
                        pid.wait()
                    if pid.poll() != 0:
                        lg.error("The ab (%s,%s) returned with error code %d\n"
                                 % (clients[i], servers[i], pid.poll()))
                        err = True
                    print("OUTPUT ab")
                    print("HHHHHHHHHHHHHHHHHHHHHHhhhh out")
                    for n in pid.stdout.readlines():
                        print(n)
                    print("HHHHHHHHHHHHHHHHHHHHHHhhhh errr")
                    for n in pid.stderr.readlines():
                        print(n)

            finally:
                for pid in tcpdumps:
                    pid.send_signal(signal.SIGINT)
                    pid.wait()
                    print("TCPDUMP")
                    print(pid.stdout.read())
                    print(pid.stderr.read())
                net.stop()
                cleanup()
                subprocess.call("pkill -9 ab".split(" "))

            if not err:
                # try:
                lg.info("******* Saving results '%s' *******\n" %
                        os.path.basename(topo))

                # Parse and save csv file
                parse_ab_output(csv_files, tcp_ebpf_experiment.abs, cwd)
                tcp_ebpf_experiment.failed = False
                tcp_ebpf_experiment.valid = True

                tc_changes = []
                for change in net.topo.applied_changes:
                    change.clean()
                    if change.applied_time >= 0:
                        tc_changes.append([change.applied_time, change.serialize()])
                tcp_ebpf_experiment.tc_changes = json.dumps(tc_changes)

                db.commit()  # Commit

                # except Exception as e:
                #    lg.error("Exception %s in the graph generation...
                #    Skipping...\n" % e)
                #    lg.error(str(e))
                #    continue
            else:
                db.commit()  # Commit even if catastrophic results
                lg.error("******* Error %s processing graphs '%s' *******\n" % (
                    err, os.path.basename(topo)))

            for pcap in pcap_files:
                if os.path.exists(pcap):
                    os.unlink(pcap)


def eval_flowbender_timer(lg, args, ovsschema):
    return eval_repetita(lg, args, ovsschema, flowbender_timer=True)


def eval_flowbender(lg, args, ovsschema):
    return eval_repetita(lg, args, ovsschema, flowbender=True)


def eval_repetita(lg, args, ovsschema, flowbender=False, flowbender_timer=False):
    topos = get_repetita_topos(args)
    os.mkdir(args.log_dir)

    lg.info("******* %d Topologies to test *******\n" % len(topos))

    measurement_time = MEASUREMENT_TIME

    db = get_connection()
    params = get_xp_params()
    if flowbender:
        params["random_strategy"] = "flowbender"
        program = SRLocalCtrl.N_RTO_CHANGER_EBPF_PROGRAM
        measurement_time = FLOWBENDER_MEASUREMENT_TIME
    elif flowbender_timer:
        params["random_strategy"] = "flowbender_timer"
        program = SRLocalCtrl.TIMEOUT_CHANGER_EBPF_PROGRAM
        measurement_time = FLOWBENDER_MEASUREMENT_TIME
    else:
        raise ValueError("Invalid combination of parameter")

    i = 0
    for topo, demands_list in topos.items():
        i += 1
        lg.info("******* [topo %d/%d] %d flow files to test in topo '%s' "
                "*******\n"
                % (i, len(topos), len(demands_list), os.path.basename(topo)))
        for demands in demands_list:
            cwd = os.path.join(args.log_dir, os.path.basename(topo) + '_' +
                               os.path.basename(demands))
            try:
                os.makedirs(cwd)
            except OSError as e:
                print("OSError %s" % e)
            cleanup()
            lg.info("******* Processing topo '%s' demands '%s' *******\n" % (
                os.path.basename(topo),
                os.path.basename(demands)))

            tcp_ebpf_experiment = \
                TCPeBPFExperiment(timestamp=datetime.now(), topology=topo,
                                  demands=demands, ebpf=args.ebpf, **params)
            db.add(tcp_ebpf_experiment)

            with open(demands) as fileobj:
                json_demands = json.load(fileobj)
            print("HHHHHHHHHHHHHHHHHHHH" + cwd)
            topo_args = {"schema_tables": ovsschema["tables"], "cwd": cwd,
                         "enable_ecn": not flowbender and not flowbender_timer,
                         "maxseg": -1, "repetita_graph": topo,
                         "ebpf": args.ebpf,
                         "json_demands": json_demands,
                         "localctrl_opts": {
                             "long_ebpf_program": program
                         }}

            net = ReroutingNet(topo=RepetitaTopo(**topo_args),
                               static_routing=True)
            result_files = []
            tcpdumps = []

            subprocess.call("pkill -9 iperf".split(" "))
            subprocess.call("pkill -9 curl".split(" "))
            subprocess.call("pkill -9 ab".split(" "))
            err = False
            try:
                net.start()

                # Read flow file to retrieve the clients and servers
                json_demands = parse_demands(json_demands)
                print(json_demands)
                clients = []
                servers = []
                nbr_flows = []
                clamp = []
                for d in json_demands:
                    clients.append("h" + net.topo.getFromIndex(d["src"]))
                    servers.append("h" + net.topo.getFromIndex(d["dest"]))
                    nbr_flows.append(d["number"])
                    clamp.append(d["volume"] // 1000)  # Mbps

                    connections = [IPerfConnections(connection_id=conn,
                                                    max_volume=clamp[-1])
                                   for conn in range(nbr_flows[-1])]
                    tcp_ebpf_experiment.iperfs.append(
                        IPerfResults(client=clients[-1], server=servers[-1],
                                     connections=connections))
                print(clients)
                print(servers)

                # IPCLI(net)  # TODO Remove
                time.sleep(1)

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                # Launch tcpdump on all clients, servers and routers
                if args.tcpdump:
                    for n in clients + servers + [r.name for r in net.routers]:
                        cmd = "tshark -F pcapng -w {}.pcapng ip6".format(os.path.join(cwd, n))
                        tcpdumps.append(net[n].popen(cmd))

                result_files = [open(os.path.join(cwd, "%d_results_%s_%s.json")
                                     % (i, clients[i], servers[i]), "w")
                                for i in range(len(clients))]
                pid_servers, pid_clients = \
                    launch_iperf(lg, net, clients, servers, result_files,
                                 nbr_flows, clamp, tcp_ebpf_experiment.iperfs,
                                 ebpf=args.ebpf, measurement_time=measurement_time)
                if len(pid_servers) == 0:
                    return

                # IPCLI(net)  # TODO Remove

                # Measure load on each interface
                start_time = time.time()
                snapshots = {h: [] for h in clients + servers}
                snap_class = FlowBenderSnapshot if flowbender or flowbender_timer else Snapshot
                while time.time() - start_time < measurement_time:
                    # Extract snapshot info from eBPF
                    if args.ebpf:
                        for h in snapshots.keys():
                            snapshots[h].extend(snap_class.extract_info(net[h]))
                            snapshots[h] = sorted(list(set(snapshots[h])))
                    # for pid in pid_servers:
                    #    print("ANOTHER SERVER")
                    #    print(pid.stdout.readlines())
                    apply_changes(time.time() - start_time, net)
                    time.sleep(0.1)

                # IPCLI(net)  # TODO Remove

                # Allow iperf control connection to recover fast
                revert_changes(net)

                # IPCLI(net)  # TODO Remove

                print("Check servers ending")
                for i, pid in enumerate(pid_servers):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        print("ERROR 0")
                        pid.send_signal(signal.SIGTERM)
                        pid.wait(10)
                        print("ERROR 1")
                        pid.kill()

                print("Check clients ending")
                for i, pid in enumerate(pid_clients):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        pid.kill()

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                for pid in tcpdumps:
                    pid.kill()
            # except Exception as e:
            #    lg.error("Exception %s in the topo emulation... Skipping...\n"
            #             % e)
            #    ipmininet.DEBUG_FLAG = True  # Do not clear daemon logs
            #    continue
            finally:

                for pid in tcpdumps:
                    pid.kill()

                # IPCLI(net)  # TODO Remove
                net.stop()
                cleanup()
                for fileobj in result_files:
                    if fileobj is not None:
                        fileobj.close()
                subprocess.call("pkill -9 iperf".split(" "))

            db.commit()  # Commit even if catastrophic results

            if not err:
                # try:
                lg.info("******* Saving results '%s' *******\n" %
                        os.path.basename(topo))
                for i in range(len(clients)):
                    with open(os.path.join(cwd, "%d_results_%s_%s.json" % (i, clients[i], servers[i])), "r") as fileobj:
                        results = json.load(fileobj)
                        iperf_db = tcp_ebpf_experiment.iperfs[i]
                        iperf_db.raw_json = json.dumps(results, indent=4)
                        for j in range(nbr_flows[i]):
                            connection_db = iperf_db.connections[j]
                            connection_db.start_samples = \
                                results["start"]["timestamp"]["timesecs"]
                        for t, interval in enumerate(results["intervals"]):
                            connection_db.bw_samples.append(
                                IPerfBandwidthSample(time=(t + 1) * INTERVALS,
                                                     bw=interval["streams"][j]["bits_per_second"]))

                for h, snaps in snapshots.items():
                    for snap in snaps:
                        tcp_ebpf_experiment.snapshots.append(
                            SnapshotDBEntry(snapshot_hex=snap.export(), host=h)
                        )

                print(len(list(tcp_ebpf_experiment.snapshots)))
                print("JJJJJJJJJJJJJJJJJJJJJJJJ")
                for snap_entry in tcp_ebpf_experiment.data_related_snapshots():
                    snap = tcp_ebpf_experiment.snap_class().retrieve_from_hex(snap_entry.snapshot_hex)
                    print(snap.time, snap.operation)
                print("JJJJJJJJJJJJJJJJJJJJJJJJ")
                tcp_ebpf_experiment.failed = False
                tcp_ebpf_experiment.valid = True

                # The delta is an approximation valid at 0.1 ms, so negligible for our use cases
                tcp_ebpf_experiment.monotonic_realtime_delta = time.time() - time.monotonic()

                tc_changes = []
                for change in net.topo.applied_changes:
                    change.clean()
                    if change.applied_time >= 0:
                        tc_changes.append([change.applied_time, change.serialize()])
                tcp_ebpf_experiment.tc_changes = json.dumps(tc_changes)

                db.commit()
                # except Exception as e:
                #    lg.error("Exception %s in the graph generation...
                #    Skipping...\n" % e)
                #    lg.error(str(e))
                #    continue
            else:
                lg.error("******* Error %s processing graphs '%s' *******\n" % (
                    err, os.path.basename(topo)))
                db.commit()  # Commit even if catastrophic results


def reverse_srh_failure(lg, args, ovsschema, flowbender_timer=False):
    topos = get_repetita_topos(args)
    os.mkdir(args.log_dir)

    lg.info("******* %d Topologies to test *******\n" % len(topos))

    db = get_connection()
    params = get_xp_params()
    params["random_strategy"] = "reverse_srh_flowbender"
    server_program = SRLocalCtrl.REVERSE_SRH_PROGRAM
    client_program = SRLocalCtrl.N_RTO_CHANGER_EBPF_PROGRAM
    measurement_time = FLOWBENDER_MEASUREMENT_TIME
    if flowbender_timer:
        params["random_strategy"] = "reverse_srh_flowbender_timer"
        client_program = SRLocalCtrl.TIMEOUT_CHANGER_EBPF_PROGRAM
        measurement_time = FLOWBENDER_MEASUREMENT_TIME

    i = 0
    for topo, demands_list in topos.items():
        i += 1
        lg.info("******* [topo %d/%d] %d flow files to test in topo '%s' "
                "*******\n"
                % (i, len(topos), len(demands_list), os.path.basename(topo)))
        for demands in demands_list:
            cwd = os.path.join(args.log_dir, os.path.basename(topo) + '_' +
                               os.path.basename(demands))
            try:
                os.makedirs(cwd)
            except OSError as e:
                print("OSError %s" % e)
            cleanup()
            lg.info("******* Processing topo '%s' demands '%s' *******\n" % (
                os.path.basename(topo),
                os.path.basename(demands)))

            tcp_ebpf_experiment = \
                TCPeBPFExperiment(timestamp=datetime.now(), topology=topo,
                                  demands=demands, ebpf=args.ebpf, **params)
            db.add(tcp_ebpf_experiment)

            with open(demands) as fileobj:
                json_demands = json.load(fileobj)
            print("HHHHHHHHHHHHHHHHHHHH" + cwd)
            topo_args = {"schema_tables": ovsschema["tables"], "cwd": cwd,
                         "enable_ecn": False,
                         "maxseg": -1, "repetita_graph": topo,
                         "ebpf": args.ebpf,
                         "json_demands": json_demands,
                         "localctrl_opts": {
                             "long_ebpf_program": client_program
                         }}

            net = ReroutingNet(topo=RepetitaTopo(**topo_args),
                               static_routing=True)
            result_files = []
            tcpdumps = []

            subprocess.call("pkill -9 iperf".split(" "))
            subprocess.call("pkill -9 curl".split(" "))
            subprocess.call("pkill -9 ab".split(" "))
            err = False
            try:
                net.start()

                # Read flow file to retrieve the clients and servers
                json_demands = parse_demands(json_demands)
                print(json_demands)
                clients = []
                servers = []
                nbr_flows = []
                clamp = []
                for d in json_demands:
                    clients.append("h" + net.topo.getFromIndex(d["src"]))
                    servers.append("h" + net.topo.getFromIndex(d["dest"]))
                    nbr_flows.append(d["number"])
                    clamp.append(d["volume"] // 1000)  # Mbps

                    connections = [IPerfConnections(connection_id=conn,
                                                    max_volume=clamp[-1])
                                   for conn in range(nbr_flows[-1])]
                    tcp_ebpf_experiment.iperfs.append(
                        IPerfResults(client=clients[-1], server=servers[-1],
                                     connections=connections))
                print(clients)
                print(servers)

                # IPCLI(net)  # TODO Remove
                time.sleep(1)

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                # Launch tcpdump on all clients, servers and routers
                if args.tcpdump:
                    for n in clients + servers + [r.name for r in net.routers]:
                        cmd = "tshark -F pcapng -w {}.pcapng ip6".format(os.path.join(cwd, n))
                        tcpdumps.append(net[n].popen(cmd))

                result_files = [open(os.path.join(cwd, "%d_results_%s_%s.json")
                                     % (i, clients[i], servers[i]), "w")
                                for i in range(len(clients))]
                pid_servers, pid_clients = \
                    launch_iperf(lg, net, clients, servers, result_files,
                                 nbr_flows, clamp, tcp_ebpf_experiment.iperfs,
                                 ebpf=args.ebpf, measurement_time=measurement_time,
                                 client_program=client_program, server_program=server_program)
                if len(pid_servers) == 0:
                    return

                # IPCLI(net)  # TODO Remove

                # Measure load on each interface
                start_time = time.time()
                snapshots = {h: [] for h in clients + servers}
                snap_class = FlowBenderSnapshot
                while time.time() - start_time < measurement_time:
                    # Extract snapshot info from eBPF
                    if args.ebpf:
                        for h in snapshots.keys():
                            snapshots[h].extend(snap_class.extract_info(net[h]))
                            snapshots[h] = sorted(list(set(snapshots[h])))
                    # for pid in pid_servers:
                    #    print("ANOTHER SERVER")
                    #    print(pid.stdout.readlines())
                    apply_changes(time.time() - start_time, net)
                    time.sleep(0.1)

                # IPCLI(net)  # TODO Remove

                # Allow iperf control connection to recover fast
                revert_changes(net)

                # IPCLI(net)  # TODO Remove

                print("Check servers ending")
                for i, pid in enumerate(pid_servers):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        print("ERROR 0")
                        pid.send_signal(signal.SIGTERM)
                        pid.wait(10)
                        print("ERROR 1")
                        pid.kill()

                print("Check clients ending")
                for i, pid in enumerate(pid_clients):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        pid.kill()

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                for pid in tcpdumps:
                    pid.kill()
            # except Exception as e:
            #    lg.error("Exception %s in the topo emulation... Skipping...\n"
            #             % e)
            #    ipmininet.DEBUG_FLAG = True  # Do not clear daemon logs
            #    continue
            finally:

                for pid in tcpdumps:
                    pid.kill()

                # IPCLI(net)  # TODO Remove
                net.stop()
                cleanup()
                for fileobj in result_files:
                    if fileobj is not None:
                        fileobj.close()
                subprocess.call("pkill -9 iperf".split(" "))

            db.commit()  # Commit even if catastrophic results

            if not err:
                # try:
                lg.info("******* Saving results '%s' *******\n" %
                        os.path.basename(topo))
                for i in range(len(clients)):
                    with open(os.path.join(cwd, "%d_results_%s_%s.json" % (i, clients[i], servers[i])), "r") as fileobj:
                        results = json.load(fileobj)
                        iperf_db = tcp_ebpf_experiment.iperfs[i]
                        iperf_db.raw_json = json.dumps(results, indent=4)
                        for j in range(nbr_flows[i]):
                            connection_db = iperf_db.connections[j]
                            connection_db.start_samples = \
                                results["start"]["timestamp"]["timesecs"]
                        for t, interval in enumerate(results["intervals"]):
                            connection_db.bw_samples.append(
                                IPerfBandwidthSample(time=(t + 1) * INTERVALS,
                                                     bw=interval["streams"][j]["bits_per_second"]))

                for h, snaps in snapshots.items():
                    for snap in snaps:
                        tcp_ebpf_experiment.snapshots.append(
                            SnapshotDBEntry(snapshot_hex=snap.export(), host=h)
                        )

                print(len(list(tcp_ebpf_experiment.snapshots)))
                print("JJJJJJJJJJJJJJJJJJJJJJJJ")
                for snap_entry in tcp_ebpf_experiment.data_related_snapshots():
                    snap = tcp_ebpf_experiment.snap_class().retrieve_from_hex(snap_entry.snapshot_hex)
                    print(snap.time, snap.operation)
                print("JJJJJJJJJJJJJJJJJJJJJJJJ")
                tcp_ebpf_experiment.failed = False
                tcp_ebpf_experiment.valid = True

                # The delta is an approximation valid at 0.1 ms, so negligible for our use cases
                tcp_ebpf_experiment.monotonic_realtime_delta = time.time() - time.monotonic()

                tc_changes = []
                for change in net.topo.applied_changes:
                    change.clean()
                    if change.applied_time >= 0:
                        tc_changes.append([change.applied_time, change.serialize()])
                tcp_ebpf_experiment.tc_changes = json.dumps(tc_changes)

                db.commit()
                # except Exception as e:
                #    lg.error("Exception %s in the graph generation...
                #    Skipping...\n" % e)
                #    lg.error(str(e))
                #    continue
            else:
                lg.error("******* Error %s processing graphs '%s' *******\n" % (
                    err, os.path.basename(topo)))
                db.commit()  # Commit even if catastrophic results


def reverse_srh_load_balancer(lg, args, ovsschema):
    topos = get_repetita_topos(args)
    os.mkdir(args.log_dir)

    lg.info("******* %d Topologies to test *******\n" % len(topos))

    db = get_connection()
    params = get_xp_params()
    params["random_strategy"] = "reverse_srh_load_balancer"
    server_program = SRLocalCtrl.USE_SECOND_PROGRAM
    client_program = SRLocalCtrl.REVERSE_SRH_PROGRAM
    measurement_time = LOAD_BALANCER_MEASUREMENT_TIME

    i = 0
    for topo, demands_list in topos.items():
        i += 1
        lg.info("******* [topo %d/%d] %d flow files to test in topo '%s' "
                "*******\n"
                % (i, len(topos), len(demands_list), os.path.basename(topo)))
        for demands in demands_list:
            cwd = os.path.join(args.log_dir, os.path.basename(topo) + '_' +
                               os.path.basename(demands))
            try:
                os.makedirs(cwd)
            except OSError as e:
                print("OSError %s" % e)
            cleanup()
            lg.info("******* Processing topo '%s' demands '%s' *******\n" % (
                os.path.basename(topo),
                os.path.basename(demands)))

            tcp_ebpf_experiment = \
                TCPeBPFExperiment(timestamp=datetime.now(), topology=topo,
                                  demands=demands, ebpf=args.ebpf, **params)
            db.add(tcp_ebpf_experiment)

            with open(demands) as fileobj:
                json_demands = json.load(fileobj)
            print("HHHHHHHHHHHHHHHHHHHH" + cwd)
            topo_args = {"schema_tables": ovsschema["tables"], "cwd": cwd,
                         "enable_ecn": False,
                         "maxseg": -1, "repetita_graph": topo,
                         "ebpf": args.ebpf,
                         "json_demands": json_demands,
                         "localctrl_opts": {
                             "long_ebpf_program": server_program
                         }}

            net = ReroutingNet(topo=RepetitaTopo(**topo_args),
                               static_routing=True)
            result_files = []
            tcpdumps = []

            subprocess.call("pkill -9 iperf".split(" "))
            subprocess.call("pkill -9 curl".split(" "))
            subprocess.call("pkill -9 ab".split(" "))
            err = False
            try:
                net.start()

                # Read flow file to retrieve the clients and servers
                json_demands = parse_demands(json_demands)
                print(json_demands)
                clients = []
                servers = []
                nbr_flows = []
                clamp = []
                for d in json_demands:
                    clients.append("h" + net.topo.getFromIndex(d["src"]))
                    servers.append("h" + net.topo.getFromIndex(d["dest"]))
                    nbr_flows.append(d["number"])
                    clamp.append(d["volume"] // 1000)  # Mbps

                    connections = [IPerfConnections(connection_id=conn,
                                                    max_volume=clamp[-1])
                                   for conn in range(nbr_flows[-1])]
                    tcp_ebpf_experiment.iperfs.append(
                        IPerfResults(client=clients[-1], server=servers[-1],
                                     connections=connections))
                print(clients)
                print(servers)

                # IPCLI(net)  # TODO Remove
                time.sleep(1)

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                # Launch tcpdump on all clients, servers and routers
                if args.tcpdump:
                    for n in clients + servers + [r.name for r in net.routers]:
                        cmd = "tshark -F pcapng -w {}.pcapng ip6".format(os.path.join(cwd, n))
                        tcpdumps.append(net[n].popen(cmd))

                result_files = [open(os.path.join(cwd, "%d_results_%s_%s.json")
                                     % (i, clients[i], servers[i]), "w")
                                for i in range(len(clients))]
                pid_servers, pid_clients = \
                    launch_iperf(lg, net, clients, servers, result_files,
                                 nbr_flows, clamp, tcp_ebpf_experiment.iperfs,
                                 ebpf=args.ebpf, measurement_time=measurement_time,
                                 client_program=client_program, server_program=server_program)
                if len(pid_servers) == 0:
                    return

                # IPCLI(net)  # TODO Remove

                # Measure load on each interface
                start_time = time.time()
                while time.time() - start_time < measurement_time:
                    # for pid in pid_servers:
                    #    print("ANOTHER SERVER")
                    #    print(pid.stdout.readlines())
                    apply_changes(time.time() - start_time, net)
                    time.sleep(0.1)

                # IPCLI(net)  # TODO Remove

                # Allow iperf control connection to recover fast
                revert_changes(net)

                # IPCLI(net)  # TODO Remove

                print("Check servers ending")
                for i, pid in enumerate(pid_servers):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        print("ERROR 0")
                        pid.send_signal(signal.SIGTERM)
                        pid.wait(10)
                        print("ERROR 1")
                        pid.kill()

                print("Check clients ending")
                for i, pid in enumerate(pid_clients):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        pid.kill()

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                for pid in tcpdumps:
                    pid.kill()
            # except Exception as e:
            #    lg.error("Exception %s in the topo emulation... Skipping...\n"
            #             % e)
            #    ipmininet.DEBUG_FLAG = True  # Do not clear daemon logs
            #    continue
            finally:

                for pid in tcpdumps:
                    pid.kill()

                # IPCLI(net)  # TODO Remove
                net.stop()
                cleanup()
                for fileobj in result_files:
                    if fileobj is not None:
                        fileobj.close()
                subprocess.call("pkill -9 iperf".split(" "))

            db.commit()  # Commit even if catastrophic results

            if not err:
                # try:
                lg.info("******* Saving results '%s' *******\n" %
                        os.path.basename(topo))
                for i in range(len(clients)):
                    with open(os.path.join(cwd, "%d_results_%s_%s.json" % (i, clients[i], servers[i])), "r") as fileobj:
                        results = json.load(fileobj)
                        iperf_db = tcp_ebpf_experiment.iperfs[i]
                        iperf_db.raw_json = json.dumps(results, indent=4)
                        for j in range(nbr_flows[i]):
                            connection_db = iperf_db.connections[j]
                            connection_db.start_samples = \
                                results["start"]["timestamp"]["timesecs"]
                        for t, interval in enumerate(results["intervals"]):
                            connection_db.bw_samples.append(
                                IPerfBandwidthSample(time=(t + 1) * INTERVALS,
                                                     bw=interval["streams"][j]["bits_per_second"]))
                tcp_ebpf_experiment.failed = False
                tcp_ebpf_experiment.valid = True

                # The delta is an approximation valid at 0.1 ms, so negligible for our use cases
                tcp_ebpf_experiment.monotonic_realtime_delta = time.time() - time.monotonic()

                tc_changes = []
                for change in net.topo.applied_changes:
                    change.clean()
                    if change.applied_time >= 0:
                        tc_changes.append([change.applied_time, change.serialize()])
                tcp_ebpf_experiment.tc_changes = json.dumps(tc_changes)

                db.commit()
                # except Exception as e:
                #    lg.error("Exception %s in the graph generation...
                #    Skipping...\n" % e)
                #    lg.error(str(e))
                #    continue
            else:
                lg.error("******* Error %s processing graphs '%s' *******\n" % (
                    err, os.path.basename(topo)))
                db.commit()  # Commit even if catastrophic results


def traceroute(lg, args, ovsschema):
    topos = get_repetita_topos(args)
    os.mkdir(args.log_dir)

    lg.info("******* %d Topologies to test *******\n" % len(topos))

    db = get_connection()
    params = get_xp_params()
    params["random_strategy"] = "traceroute"
    server_program = SRLocalCtrl.TRACEROUTE
    client_program = SRLocalCtrl.TRACEROUTE
    measurement_time = TRACEROUTE_MEASUREMENT_TIME

    i = 0
    for topo, demands_list in topos.items():
        i += 1
        lg.info("******* [topo %d/%d] %d flow files to test in topo '%s' "
                "*******\n"
                % (i, len(topos), len(demands_list), os.path.basename(topo)))
        for demands in demands_list:
            cwd = os.path.join(args.log_dir, os.path.basename(topo) + '_' +
                               os.path.basename(demands))
            try:
                os.makedirs(cwd)
            except OSError as e:
                print("OSError %s" % e)
            cleanup()
            lg.info("******* Processing topo '%s' demands '%s' *******\n" % (
                os.path.basename(topo),
                os.path.basename(demands)))

            tcp_ebpf_experiment = \
                TCPeBPFExperiment(timestamp=datetime.now(), topology=topo,
                                  demands=demands, ebpf=args.ebpf, **params)
            db.add(tcp_ebpf_experiment)

            with open(demands) as fileobj:
                json_demands = json.load(fileobj)
            print("HHHHHHHHHHHHHHHHHHHH" + cwd)
            topo_args = {"schema_tables": ovsschema["tables"], "cwd": cwd,
                         "enable_ecn": False,
                         "maxseg": -1, "repetita_graph": topo,
                         "ebpf": args.ebpf,
                         "json_demands": json_demands,
                         "localctrl_opts": {
                             "reverse_srh_ebpf_program": SRLocalCtrl.TRACEROUTE
                         }}

            net = ReroutingNet(topo=RepetitaTopo(**topo_args),
                               static_routing=True)
            result_files = []
            tcpdumps = []

            subprocess.call("pkill -9 iperf".split(" "))
            subprocess.call("pkill -9 curl".split(" "))
            subprocess.call("pkill -9 ab".split(" "))
            err = False
            try:
                net.start()

                # Read flow file to retrieve the clients and servers
                json_demands = parse_demands(json_demands)
                print(json_demands)
                clients = []
                servers = []
                nbr_flows = []
                clamp = []
                for d in json_demands:
                    clients.append("h" + net.topo.getFromIndex(d["src"]))
                    servers.append("h" + net.topo.getFromIndex(d["dest"]))
                    nbr_flows.append(d["number"])
                    clamp.append(d["volume"] // 1000)  # Mbps

                    connections = [IPerfConnections(connection_id=conn,
                                                    max_volume=clamp[-1])
                                   for conn in range(nbr_flows[-1])]
                    tcp_ebpf_experiment.iperfs.append(
                        IPerfResults(client=clients[-1], server=servers[-1],
                                     connections=connections))
                print(clients)
                print(servers)

                # IPCLI(net)  # TODO Remove
                time.sleep(1)

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                # Launch tcpdump on all clients, servers and routers
                if args.tcpdump:
                    for n in clients + servers + [r.name for r in net.routers]:
                        cmd = "tshark -F pcapng -w {}.pcapng ip6".format(os.path.join(cwd, n))
                        tcpdumps.append(net[n].popen(cmd))

                result_files = [open(os.path.join(cwd, "%d_results_%s_%s.json")
                                     % (i, clients[i], servers[i]), "w")
                                for i in range(len(clients))]
                pid_servers, pid_clients = \
                    launch_iperf(lg, net, clients, servers, result_files,
                                 nbr_flows, clamp, tcp_ebpf_experiment.iperfs,
                                 ebpf=args.ebpf, measurement_time=measurement_time,
                                 client_program=client_program, server_program=server_program)
                if len(pid_servers) == 0:
                    return

                time.sleep(measurement_time)

                print("Check servers ending")
                for i, pid in enumerate(pid_servers):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        print("ERROR 0")
                        pid.send_signal(signal.SIGTERM)
                        pid.wait(10)
                        print("ERROR 1")
                        pid.kill()

                print("Check clients ending")
                for i, pid in enumerate(pid_clients):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        pid.kill()

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                for pid in tcpdumps:
                    pid.kill()

                for node in net.routers:
                    print(node.name)
                    for itf in node.intfList():
                        for ip6 in itf.ip6s(exclude_lls=True):
                            print(ip6.ip.compressed)
            # except Exception as e:
            #    lg.error("Exception %s in the topo emulation... Skipping...\n"
            #             % e)
            #    ipmininet.DEBUG_FLAG = True  # Do not clear daemon logs
            #    continue
            finally:

                for pid in tcpdumps:
                    pid.kill()

                # IPCLI(net)  # TODO Remove
                net.stop()
                cleanup()
                for fileobj in result_files:
                    if fileobj is not None:
                        fileobj.close()
                subprocess.call("pkill -9 iperf".split(" "))

            db.commit()  # Commit even if catastrophic results

            if not err:
                # try:
                lg.info("******* Saving results '%s' *******\n" %
                        os.path.basename(topo))
                for i in range(len(clients)):
                    with open(os.path.join(cwd, "%d_results_%s_%s.json" % (i, clients[i], servers[i])), "r") as fileobj:
                        results = json.load(fileobj)
                        iperf_db = tcp_ebpf_experiment.iperfs[i]
                        iperf_db.raw_json = json.dumps(results, indent=4)
                        for j in range(nbr_flows[i]):
                            connection_db = iperf_db.connections[j]
                            connection_db.start_samples = \
                                results["start"]["timestamp"]["timesecs"]
                        for t, interval in enumerate(results["intervals"]):
                            connection_db.bw_samples.append(
                                IPerfBandwidthSample(time=(t + 1) * INTERVALS,
                                                     bw=interval["streams"][j]["bits_per_second"]))
                tcp_ebpf_experiment.failed = False
                tcp_ebpf_experiment.valid = True

                # The delta is an approximation valid at 0.1 ms, so negligible for our use cases
                tcp_ebpf_experiment.monotonic_realtime_delta = time.time() - time.monotonic()

                db.commit()

                # except Exception as e:
                #    lg.error("Exception %s in the graph generation...
                #    Skipping...\n" % e)
                #    lg.error(str(e))
                #    continue
            else:
                lg.error("******* Error %s processing graphs '%s' *******\n" % (
                    err, os.path.basename(topo)))
                db.commit()  # Commit even if catastrophic results
