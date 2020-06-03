import csv
import json
import os
import signal
import subprocess
import time
from datetime import datetime
from shlex import split, shlex
from typing import List

from ipmininet.tests.utils import assert_connectivity
from sr6mininet.cli import SR6CLI

from examples.repetita_network import RepetitaTopo
from reroutemininet.clean import cleanup
from reroutemininet.net import ReroutingNet
from .bpf_stats import Snapshot, BPFPaths, ShortSnapshot
from .db import get_connection, TCPeBPFExperiment, IPerfResults, \
    IPerfConnections, IPerfBandwidthSample, SnapshotDBEntry, \
    SnapshotShortDBEntry
from .db.ab_results import ABLatencyCDF, ABResults
from .db.short_tcp_ebpf_experiment import ShortTCPeBPFExperiment
from .utils import get_addr, MEASUREMENT_TIME, INTERVALS


# LINK_BANDWIDTH = 100


def get_current_congestion_control():
    out = subprocess.check_output(["sysctl",
                                   "net.ipv4.tcp_congestion_control"],
                                  universal_newlines=True)
    return out.split(" = ")[-1][:-1]


def get_current_parameter(parameter_name):
    param_value = None
    with open(os.path.expanduser("~/ebpf_hhf/param.h")) as fileobj:
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
                 iperfs_db, ebpf=True):
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
            pid_servers.append(net[server].run_cgroup(cmd,
                                                      stdout=result_files[i]))
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
                    nbr_connections=nbr_flows[i], duration=MEASUREMENT_TIME,
                    intervals=INTERVALS, port=ports[i], clamp=clamp[i])
        print("%s %s" % (client, cmd))
        iperfs_db[i].cmd_client = cmd
        if ebpf:
            pid_clients.append(
                net[client].run_cgroup(cmd, stderr=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL))
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
        for root, directories, files in os.walk(os.path.dirname(repetita_topo)):
            for f in files:
                if ".flows" in f and topo_name.split(".graph")[0] in f:
                    topos.setdefault(repetita_topo, []).append(
                        os.path.join(root, f))
    return topos


def launch_ab(lg, net, clients, servers, nbr_flows, db_entry, csv_files,
              ebpf=True) -> List[subprocess.Popen]:
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
                    nbr_connections=nbr_flows[i], duration=MEASUREMENT_TIME)
        db_entry[i].cmd_client = cmd
        print(client)
        print(cmd)
        # Always run outside of the eBPF (use case where we only control
        # servers)
        pid_clients.append(net[client].popen(split(cmd)))

    return pid_clients


def parse_ab_output(csv_files, db_entry: List[ABResults]):
    for i, cvs_file in enumerate(csv_files):
        with open(cvs_file) as file_obj:
            raw_data = file_obj.read()
            db_entry[i].raw_csv = raw_data
            for j, row in enumerate(csv.DictReader(raw_data.splitlines())):
                if j == 0:  # Skip headline
                    continue
                print(row)
                # Insert in database
                db_entry[i].ab_latency_cdf.append(
                    ABLatencyCDF(
                        percentage_served=float(row["Percentage served"]),
                        time=float(row["Time in ms"])))
        # TODO Clean the file


def get_xp_params():
    return {
        "congestion_control": get_current_congestion_control(),
        "gamma_value": get_current_gamma(),
        "random_strategy": get_current_rand_type(),
        "max_reward_factor": get_current_max_reward_factor(),
        "wait_before_initial_move": get_wait_before_initial_move(),
        "wait_unstable_rtt": get_wait_unstable_rtt()
    }


def short_flows(lg, args, ovsschema):
    topos = get_repetita_topos(args)
    os.mkdir(args.log_dir)

    lg.info("******* %d Topologies to test *******\n" % len(topos))
    db = get_connection()
    params = get_xp_params()

    i = 0
    for topo, demands_list in topos.items():
        i += 1
        lg.info("******* [topo %d/%d] %d flow files to test in topo '%s' "
                "*******\n"
                % (i, len(topos), len(demands_list), os.path.basename(topo)))
        for demands in demands_list:
            cwd = os.path.join(args.log_dir, os.path.basename(demands))
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
                                       **params)
            db.add(tcp_ebpf_experiment)

            with open(demands) as fileobj:
                json_demands = json.load(fileobj)
            topo_args = {"schema_tables": ovsschema["tables"],
                         "cwd": os.path.join(args.log_dir,
                                             os.path.basename(demands)),
                         "ebpf_program": os.path.expanduser(
                             "~/ebpf_hhf/ebpf_socks_ecn.o"),
                         "always_redirect": True,
                         "maxseg": -1, "repetita_graph": topo,
                         "ebpf": args.ebpf,
                         "json_demands": json_demands}

            net = ReroutingNet(topo=RepetitaTopo(**topo_args),
                               static_routing=True)

            subprocess.call("pkill -9 iperf".split(" "))
            subprocess.call("pkill -9 curl".split(" "))
            subprocess.call("pkill -9 ab".split(" "))
            err = False
            csv_files = []
            tcpdumps = []
            try:
                net.start()

                # Read flow file to retrieve the clients and servers
                json_demands = parse_demands(json_demands)
                print(json_demands)
                clients = []
                servers = []
                nbr_flows = []
                for d in json_demands:
                    clients.append("h" + net.topo.getFromIndex(d["src"]))
                    servers.append("h" + net.topo.getFromIndex(d["dest"]))
                    nbr_flows.append(d["number"])
                    csv_files.append("%s-%s" % (clients[-1], servers[-1]))
                    tcp_ebpf_experiment.abs.append(
                        ABResults(client=clients[-1], server=servers[-1],
                                  timeout=MEASUREMENT_TIME))
                print(clients)
                print(servers)

                # Launch tcpdump on client
                if args.tcpdump:
                    for n in clients + servers + [r.name for r in net.routers]:
                        cmd = "tcpdump -w {}.pcapng ip6".format(n)
                        tcpdumps.append(net[n].popen(cmd))

                pid_abs = launch_ab(lg, net, clients, servers, nbr_flows,
                                    db_entry=tcp_ebpf_experiment.abs,
                                    csv_files=csv_files, ebpf=args.ebpf)
                if len(pid_abs) == 0:
                    return

                # SR6CLI(net)  # TODO Remove

                # Measure load on each interface
                t = 0
                snapshots = {h: [] for h in clients + servers}
                while t < MEASUREMENT_TIME:
                    # Extract snapshot info from eBPF
                    if args.ebpf:
                        for h in snapshots.keys():
                            snapshots[h].extend(
                                ShortSnapshot.extract_info(net[h]))
                            snapshots[h] = sorted(list(set(snapshots[h])))
                    time.sleep(0.1)
                    t += 0.1

                # SR6CLI(net)  # TODO Remove
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
                    pid.kill()
                net.stop()
                cleanup()
                subprocess.call("pkill -9 ab".split(" "))

            db.commit()  # Commit even if catastrophic results

            if not err:
                # try:
                lg.info("******* Saving results '%s' *******\n" %
                        os.path.basename(topo))

                # Parse and save csv file
                parse_ab_output(csv_files, tcp_ebpf_experiment.abs)
                tcp_ebpf_experiment.failed = False
                tcp_ebpf_experiment.valid = True
                db.commit()  # Commit

                # except Exception as e:
                #    lg.error("Exception %s in the graph generation...
                #    Skipping...\n" % e)
                #    lg.error(str(e))
                #    continue
            else:
                lg.error("******* Error %s processing graphs '%s' *******\n" % (
                    err, os.path.basename(topo)))


def eval_repetita(lg, args, ovsschema):
    topos = get_repetita_topos(args)
    os.mkdir(args.log_dir)

    lg.info("******* %d Topologies to test *******\n" % len(topos))

    db = get_connection()
    params = get_xp_params()

    i = 0
    for topo, demands_list in topos.items():
        i += 1
        lg.info("******* [topo %d/%d] %d flow files to test in topo '%s' "
                "*******\n"
                % (i, len(topos), len(demands_list), os.path.basename(topo)))
        for demands in demands_list:
            cwd = os.path.join(args.log_dir, os.path.basename(demands))
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
            topo_args = {"schema_tables": ovsschema["tables"],
                         "cwd": os.path.join(args.log_dir,
                                             os.path.basename(demands)),
                         "ebpf_program": os.path.expanduser(
                             "~/ebpf_hhf/ebpf_socks_ecn.o"),
                         "always_redirect": True,
                         "maxseg": -1, "repetita_graph": topo,
                         "ebpf": args.ebpf,
                         "json_demands": json_demands}

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

                # SR6CLI(net)  # TODO Remove
                time.sleep(1)
                # TODO Remove
                time.sleep(MEASUREMENT_TIME / 4)
                # TODO Remove

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                # Launch tcpdump on all clients, servers and routers
                if args.tcpdump:
                    for n in clients + servers + [r.name for r in net.routers]:
                        cmd = "tcpdump -w {}.pcapng ip6".format(n)
                        tcpdumps.append(net[n].popen(cmd))

                result_files = [open("%d_results_%s_%s.json"
                                     % (i, clients[i], servers[i]), "w")
                                for i in range(len(clients))]
                pid_servers, pid_clients = \
                    launch_iperf(lg, net, clients, servers, result_files,
                                 nbr_flows, clamp, tcp_ebpf_experiment.iperfs,
                                 ebpf=args.ebpf)
                if len(pid_servers) == 0:
                    return

                # SR6CLI(net)  # TODO Remove

                # Measure load on each interface
                t = 0
                snapshots = {h: [] for h in clients + servers}
                while t < MEASUREMENT_TIME:
                    # Extract snapshot info from eBPF
                    if args.ebpf:
                        for h in snapshots.keys():
                            snapshots[h].extend(Snapshot.extract_info(net[h]))
                            snapshots[h] = sorted(list(set(snapshots[h])))
                    #for pid in pid_servers:
                    #    print("ANOTHER SERVER")
                    #    print(pid.stdout.readlines())
                    time.sleep(1)
                    t += 1

                # SR6CLI(net)  # TODO Remove

                print("Check servers ending")
                for i, pid in enumerate(pid_servers):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        print("ERROR 0")
                        pid.send_signal(signal.SIGTERM)
                        pid.wait()
                        print("ERROR 1")
                        for line in pid.stderr.readlines():
                            print("\t%s" % line[:-1])
                        pid.kill()

                print("Check clients ending")
                for i, pid in enumerate(pid_clients):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        print("OUTPUT")
                        for line in pid.stdout.readlines():
                            print("\t%s" % line[:-1])
                        print("ERROR")
                        for line in pid.stderr.readlines():
                            print("\t%s" % line[:-1])
                        pid.kill()

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                for pid in tcpdumps:
                    pid.kill()
            #except Exception as e:
            #    lg.error("Exception %s in the topo emulation... Skipping...\n"
            #             % e)
            #    ipmininet.DEBUG_FLAG = True  # Do not clear daemon logs
            #    continue
            finally:
                for pid in tcpdumps:
                    pid.kill()

                # SR6CLI(net)  # TODO Remove
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
                # Extract JSON output
                for i in range(len(clients)):
                    with open("%d_results_%s_%s.json"
                              % (i, clients[i], servers[i]), "r") \
                            as fileobj:
                        results = json.load(fileobj)
                        iperf_db = tcp_ebpf_experiment.iperfs[i]
                        iperf_db.raw_json = json.dumps(results, indent=4)
                        for j in range(nbr_flows[i]):
                            connection_db = iperf_db.connections[j]
                            connection_db.start_samples = \
                                results["start"]["timestamp"]["timesecs"]
                            for t, interval in enumerate(results["intervals"]):
                                connection_db.bw_samples.append(
                                    IPerfBandwidthSample(
                                        time=(t + 1) * INTERVALS,
                                        bw=interval["streams"][j][
                                            "bits_per_second"])
                                )

                for h, snaps in snapshots.items():
                    for snap in snaps:
                        tcp_ebpf_experiment.snapshots.append(
                            SnapshotDBEntry(snapshot_hex=snap.export(), host=h)
                        )

                try:
                    os.makedirs(cwd)
                except OSError as e:
                    print("OSError %s" % e)
                tcp_ebpf_experiment.failed = False
                tcp_ebpf_experiment.valid = True
                db.commit()  # Commit even if catastrophic results
                # except Exception as e:
                #    lg.error("Exception %s in the graph generation...
                #    Skipping...\n" % e)
                #    lg.error(str(e))
                #    continue
            else:
                lg.error("******* Error %s processing graphs '%s' *******\n" % (
                    err, os.path.basename(topo)))
                db.commit()  # Commit even if catastrophic results
