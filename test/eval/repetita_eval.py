import json
import os
import signal
import subprocess
import time
from datetime import datetime
from multiprocessing import Value
from shlex import split

from ipmininet.tests.utils import assert_connectivity
from numpy.random import zipf, poisson

from examples.repetita_network import RepetitaTopo
from reroutemininet.clean import cleanup
from reroutemininet.net import ReroutingNet
from .bpf_stats import Snapshot, BPFPaths
from .db import get_connection, TCPeBPFExperiment, IPerfResults, \
    IPerfConnections, IPerfBandwidthSample, SnapshotDBEntry
from .utils import get_addr, MEASUREMENT_TIME

# LINK_BANDWIDTH = 100

INTERVALS = 1


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


def launch_iperf(lg, net, clients, servers, result_files, nbr_flows, iperfs_db,
                 ebpf=True):
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
        cmd = "iperf3 -J -s -p %d" % ports[i]
        iperfs_db[i].cmd_server = cmd
        if ebpf:
            pid_servers.append(net[server].run_cgroup(cmd, stdout=result_files[i]))
        else:
            pid_servers.append(net[server].popen(split(cmd), stdout=result_files[i]))
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
        cmd = "iperf3 -J -P {nbr_connections} -c {server_ip} -t {duration} " \
              "-B {client_ip} -i {intervals} -p {port}" \
            .format(server_ip=get_addr(net[servers[i]]),
                    client_ip=get_addr(net[client]),
                    nbr_connections=nbr_flows[i], duration=MEASUREMENT_TIME,
                    intervals=INTERVALS, port=ports[i])
        iperfs_db[i].cmd_client = cmd
        if ebpf:
            pid_clients.append(net[client].run_cgroup(cmd))
        else:
            pid_clients.append(net[client].popen(split(cmd)))
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


def cs_name(client, server, nbr_conn):
    return "%s-%s.%d" % (client, server, nbr_conn)


def send_interactive_traffic(queue, curl_cfg, ebpf, stop, client, server):

    while stop.value == 0:
        # Random sleep around 0.5 sec
        time.sleep(poisson(0.5))

        # Byte size
        # From Figure 5 in "How Speedy is SPDY"
        file_size = zipf(750000 + 10 * 20000)

        # Query it
        start_connection = time.time()
        cmd = "curl '@{cfg}' -o /dev/null -r 0-{file_size} -s" \
              " http://[{ip6}]/mock_file"\
            .format(cfg=curl_cfg, ip6=server.ip6, file_size=file_size)
        if ebpf:
            curl = client.run_cgroup(cmd)
        else:
            curl = client.popen(split(cmd))

        out, err = curl.communicate()
        data = json.loads(out.decode("utf-8"))
        data["http_client"] = client.name
        data["http_server"] = server.name
        queue.put(data)

    return 0


def parse_demands(json_demands):
    """Fuse demands with the same destination and source"""

    merged_demands = {}
    for demand in json_demands:
        demand["number"] = 1
        str_key = "%s-%s" % (demand["src"], demand["dest"])
        if str_key in merged_demands:
            merged_demands[str_key]["number"] += 1
        else:
            merged_demands[str_key] = demand

    return [x for x in merged_demands.values()]


def eval_repetita(lg, args, ovsschema):
    topos = {}
    if args.repetita_topo is None and args.repetita_dir is None:
        return
    if args.repetita_dir is not None:
        for root, directories, files in os.walk(args.repetita_dir):
            for f in files:
                if ".graph" in f:
                    # Identify related flow files
                    for flow_name in files:
                        if ".flows" in flow_name and f.split(".")[0] in flow_name:
                            topos.setdefault(os.path.join(root, f), []).append(os.path.join(root, flow_name))

    if args.repetita_topo is not None:
        repetita_topo = os.path.abspath(args.repetita_topo)
        topo_name = os.path.basename(args.repetita_topo)
        print(args.repetita_topo)
        for root, directories, files in os.walk(os.path.dirname(repetita_topo)):
            for f in files:
                if ".flows" in f and topo_name.split(".graph")[0] in f:
                    topos.setdefault(repetita_topo, []).append(
                        os.path.join(root, f))

    os.mkdir(args.log_dir)

    lg.info("******* %d Topologies to test *******\n" % len(topos))

    db = get_connection()
    cc = get_current_congestion_control()
    gamma = get_current_gamma()
    rand_type = get_current_rand_type()

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
                                  demands=demands, congestion_control=cc,
                                  gamma_value=gamma, random_strategy=rand_type,
                                  ebpf=args.ebpf)
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
            subprocess.call("pkill -9 lighttpd".split(" "))
            subprocess.call("pkill -9 curl".split(" "))
            err = False
            interactives = []
            stop = Value("i")
            stop.value = 0
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

                    connections = [IPerfConnections(connection_id=conn)
                                   for conn in range(nbr_flows[-1])]
                    tcp_ebpf_experiment.iperfs.append(
                        IPerfResults(client=clients[-1], server=servers[-1],
                                     connections=connections))
                print(clients)
                print(servers)

                # SR6CLI(net)  # TODO Remove
                time.sleep(1)
                # TODO Remove
                time.sleep(30)
                # TODO Remove

                # Recover eBPF maps
                if args.ebpf:
                    for node in clients + servers:
                        # TODO Do something with the info ?
                        print(BPFPaths.extract_info(net, net[node]))
                        break

                result_files = [open("%d_results_%s_%s.json"
                                     % (i, clients[i], servers[i]), "w")
                                for i in range(len(clients))]
                pid_servers, pid_clients = \
                    launch_iperf(lg, net, clients, servers, result_files,
                                 nbr_flows, tcp_ebpf_experiment.iperfs,
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
                    time.sleep(1)
                    t += 1

                # SR6CLI(net)  # TODO Remove

                for i, pid in enumerate(pid_clients):
                    if pid.poll() is None:
                        lg.error("The iperf (%s,%s) has not finish yet\n" % (clients[i], servers[i]))
                        pid.send_signal(signal.SIGINT)
                        pid.wait()
                    if pid.poll() != 0:
                        lg.error("The iperf (%s,%s) returned with error code %d\n"
                                 % (clients[i], servers[i], pid.poll()))
                        err = True

                for pid in pid_servers:
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
                stop.value = 1
                for process in interactives:
                    process.join(timeout=30)
                    if process.is_alive():
                        process.kill()
                        process.join()

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
