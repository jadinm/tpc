import json
import os
import re
import subprocess
import time
import ipmininet
from shlex import split
from numpy.random import zipf, poisson
from multiprocessing import Process, Value, Queue

import matplotlib.pyplot as plt
from ipmininet.tests.utils import assert_connectivity
from sr6mininet.cli import SR6CLI
import signal

from examples.albilene import Albilene
from examples.repetita_network import RepetitaTopo
from reroutemininet.clean import cleanup
from reroutemininet.net import ReroutingNet
from .bpf_stats import Snapshot, BPFPaths
from .utils import get_addr, debug_tcpdump, FONTSIZE, MEASUREMENT_TIME

#LINK_BANDWIDTH = 100

INTERVALS = 1


def launch_iperf(lg, net, clients, servers, result_files, nbr_flows, ebpf=True):
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


def measure_link_load(net, timestamps, byte_loads, packet_loads):
    regex = re.compile(r'\s+')
    for router in net.routers:
        out = router.cmd(split("cat /proc/net/dev"))
        lines = out.split("\n")[2:]
        for line in lines:
            items = regex.split(line)
            if len(items) < 3:
                continue
            if len(items[0]) == 0:
                items = items[1:]
            itf_name = items[0][:-1]
            if itf_name != 'lo':
                itf = router.intf(itf_name)
                byte_loads.setdefault(itf.name, []).append(int(items[1]))
                packet_loads.setdefault(itf.name, []).append(int(items[2]))
    timestamps.append(int(round(time.time())))


def plot(lg, times, bw, output_path, snapshots, unaggregated_bw, ebpf=True,
         identifier=None):

    suffix = "ebpf" if ebpf else "no-ebpf"

    # Bandwidth
    figure_name = "bw_repetita_iperf_%s" % suffix
    fig = plt.figure()
    subplot = fig.add_subplot(111)
    x = times
    bw = [float(b) / 10**6 for b in bw]
    print(unaggregated_bw)
    unaggregated_bw = [[float(b) / 10**6 for b in bw_list]
                       for bw_list in unaggregated_bw]
    print(unaggregated_bw)
    print(bw)
    print(x)

    subplot.step(x, bw, color="#00B0F0", marker="o", linewidth=2.0, where="post",
                 markersize=5, zorder=2)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Bandwidth (Mbps)", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0)
    subplot.set_xlim(left=0, right=MEASUREMENT_TIME)

    pdf = os.path.join(output_path, "%s.pdf" % figure_name)
    lg.info("Save figure for bandwidth to %s\n" % pdf)
    fig.savefig(pdf, bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    json_file = os.path.join(output_path, "repetita_%s.json" % suffix)
    lg.info("Saving raw data to %s\n" % json_file)
    with open(json_file, "w") as file:
        json.dump({"bw": {times[i]: bw[i] for i in range(len(bw))},
                   "unaggregated_bw": {times[i]: unaggregated_bw[i] for i in range(len(unaggregated_bw))},
                   "id": identifier,
                   "snapshots": {h: [snap.export() for snap in snaps]
                                 for h, snaps in snapshots.items()}},
                  file, indent=4)


def plot_link_loads(lg, times, byte_loads, packet_loads, output_path, ebpf=True, identifier=None):

    suffix = "ebpf" if ebpf else "no-ebpf"

    # Bandwidth
    figure_name = "link_loads_repetita_iperf_%s" % suffix
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    subplot.boxplot(byte_loads)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Link load (%)", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0)
    subplot.set_xlim(left=0, right=MEASUREMENT_TIME)

    lg.info("Save figure for link load\n")
    fig.savefig(os.path.join(output_path, "%s.pdf" % figure_name),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    # Packet per seconds
    figure_name = "pkts_per_seconds_repetita_iperf_%s" % suffix
    fig = plt.figure()
    subplot = fig.add_subplot(111)

    subplot.boxplot(packet_loads)

    subplot.set_xlabel("Time (s)", fontsize=FONTSIZE)
    subplot.set_ylabel("Link load (packets/s)", fontsize=FONTSIZE)
    subplot.set_ylim(bottom=0)
    subplot.set_xlim(left=0, right=MEASUREMENT_TIME)

    lg.info("Save figure for link loads in packet per seconds\n")
    fig.savefig(os.path.join(output_path, "%s.pdf" % figure_name),
                bbox_inches='tight', pad_inches=0, markersize=9)
    fig.clf()
    plt.close()

    lg.info("Saving raw data\n")
    with open(os.path.join(output_path, "link_load_repetita_%s.json" % suffix), "w") as file:
        json.dump({"byte_loads": {times[i]: byte_loads[i] for i in range(len(byte_loads))},
                   "packet_loads": {times[i]: packet_loads[i] for i in range(len(packet_loads))},
                   "id": identifier}, file, indent=4)


def cs_name(client, server):
    return "%s-%s" % (client, server)


def aggregate_bandwidth(clients, servers, start, bw):
    indexes = [0 for _ in range(len(clients))]
    times = set()
    aggregated_bw = {}
    current_bw = [0 for _ in range(len(clients))]
    unaggregated_bw = {}

    # Aggregate all measurements in order until None can be found

    while not all([indexes[i] >= len(bw[cs_name(clients[i], servers[i])]) for i in range(len(clients))]):
        # Get next minimum time
        next_min_time = None
        next_i = 0
        for i in range(len(clients)):
            if indexes[i] >= len(bw[cs_name(clients[i], servers[i])]):  # No more values to unpack
                continue
            next_time = start[cs_name(clients[i], servers[i])] + indexes[i] * INTERVALS
            if next_min_time is None or next_min_time > next_time:
                next_min_time = next_time
                next_i = i

        # Update current bandwidth and add timestamp
        times.add(next_min_time)
        current_bw[next_i] = bw[cs_name(clients[next_i], servers[next_i])][indexes[next_i]]
        indexes[next_i] += 1
        aggregated_bw[next_min_time] = sum(current_bw)
        unaggregated_bw[next_min_time] = current_bw

    aggregated_bw = [(timestamp, bw) for timestamp, bw in aggregated_bw.items()]
    aggregated_bw.sort()
    aggregated_bw = [elem[1] for elem in aggregated_bw]

    unaggregated_bw = [(timestamp, bw) for timestamp, bw in unaggregated_bw.items()]
    unaggregated_bw.sort()
    unaggregated_bw = [elem[1] for elem in unaggregated_bw]

    times = sorted(list(times))
    start = times[0]
    times = [x - start for x in times]

    return times, aggregated_bw, unaggregated_bw


def post_process_link_loads(net, timestamps, byte_loads, packet_loads):

    times = [t - timestamps[0] for t in timestamps][1:]

    for itf_name in list(byte_loads.keys()):
        for r in net.routers:
            try:
                itf = r.intf(itf_name)
            except KeyError:
                continue
            if itf.bw > 0:  # Router link
                b = []
                p = []
                for i in range(1, len(byte_loads[itf_name])):
                    b.append(float((byte_loads[itf_name][i] - byte_loads[itf_name][i - 1]) / 10 ** 6 * 8)
                             / float(itf.bw))
                    p.append(packet_loads[itf_name][i] - packet_loads[itf_name][i - 1])
                byte_loads[itf_name] = b
                packet_loads[itf_name] = p
            else:
                del byte_loads[itf_name]
                del packet_loads[itf_name]
            break

    bloads = []
    ploads = []
    for i in range(len(times)):
        bloads.append([])
        ploads.append([])
        for itf_name in byte_loads.keys():
            bloads[i].append(byte_loads[itf_name][i])
            ploads[i].append(packet_loads[itf_name][i])

    return times, bloads, ploads


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
                    topos.setdefault(repetita_topo, []).append(os.path.join(root, f))

    os.mkdir(args.log_dir)

    # Create curl_cfg
    curl_cfg = os.path.join(args.log_dir, "curl.cfg")
    with open(curl_cfg, "w") as fileobj:
        fileobj.write("""
        {
            "size_download": %{size_download},
            "http_code": %{http_code},
            "speed_download": %{speed_download},
            "time_total": %{time_total}
        }
        """)

    lg.info("******* %d Topologies to test *******\n" % len(topos))

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
            timestamps = []
            byte_loads = {}
            packet_loads = {}
            lg.info("******* Processing topo '%s' demands '%s' *******\n" % (os.path.basename(topo),
                                                                             os.path.basename(demands)))

            with open(demands) as fileobj:
                json_demands = json.load(fileobj)
            topo_args = {"schema_tables": ovsschema["tables"],
                         "cwd": os.path.join(args.log_dir,
                                             os.path.basename(demands)),
                         "ebpf_program": os.path.expanduser("~/ebpf_hhf/ebpf_socks_ecn.o"),
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
            queue = Queue()
            try:
                net.start()

                # Read flow file to retrieve the clients and servers
                json_demands = parse_demands(json_demands)
                print(json_demands)
                clients = ["h" + net.topo.getFromIndex(d["src"]) for d in json_demands]
                servers = ["h" + net.topo.getFromIndex(d["dest"]) for d in json_demands]
                nbr_flows = [d["number"] for d in json_demands]
                print(clients)
                print(servers)
                if args.tcpdump:
                    for h in clients + servers:
                        tcpdumps.extend(debug_tcpdump(net[h], h + "-eth0",
                                                      os.path.join(
                                                      args.log_dir, os.path.basename(topo)),
                                                      out_prefix="ebpf" if
                                                      args.ebpf else ""))

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

                # Launch interactive traffic
                if args.with_interactive:
                    lg.info("*********Starting interactive traffic*********\n")
                    for i in range(len(servers)):
                        # Client and servers are reversed because we want the
                        # traffic to go in the same direction as iperf traffic
                        interactives.append(
                            Process(target=send_interactive_traffic,
                                    args=(queue, curl_cfg, args.ebpf, stop,
                                          servers[i], clients[i])))
                        interactives[-1].start()

                result_files = [open("%d_results_%s_%s.json"
                                     % (i, clients[i], servers[i]), "w")
                                for i in range(len(clients))]
                pid_servers, pid_clients = launch_iperf(lg, net, clients,
                                                        servers,
                                                        result_files, nbr_flows,
                                                        ebpf=args.ebpf)
                if len(pid_servers) == 0:
                    return

                # SR6CLI(net)  # TODO Remove

                # Measure load on each interface
                t = 0
                snapshots = {h: [] for h in clients + servers}
                while t < MEASUREMENT_TIME:
                    # Get all link loads
                    measure_link_load(net, timestamps, byte_loads, packet_loads)
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
                if len(timestamps) > 0:
                    timestamps, byte_loads, packet_loads = \
                        post_process_link_loads(net, timestamps, byte_loads,
                                                packet_loads)
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

            if not err:
                #try:
                lg.info("******* Plotting graphs '%s' *******\n" %
                        os.path.basename(topo))
                # Extract JSON output
                bw = {}
                start = {}
                for i in range(len(clients)):
                    with open("%d_results_%s_%s.json"
                              % (i, clients[i], servers[i]), "r") \
                            as fileobj:
                        results = json.load(fileobj)
                        start[cs_name(clients[i], servers[i])] = results["start"]["timestamp"]["timesecs"]
                        for interval in results["intervals"]:
                            bw.setdefault(cs_name(clients[i], servers[i]), []).append(interval["sum"]["bits_per_second"])

                times, aggregated_bw, unaggregated_bw = \
                    aggregate_bandwidth(clients, servers, start, bw)

                try:
                    os.makedirs(cwd)
                except OSError as e:
                    print("OSError %s" % e)
                plot(lg, times, aggregated_bw, cwd, snapshots,
                     unaggregated_bw, ebpf=args.ebpf,
                     identifier={"topo": os.path.basename(topo), "demands": os.path.basename(demands),
                                 "ebpf": args.ebpf, "maxseg": -1})
                plot_link_loads(lg, timestamps, byte_loads, packet_loads, cwd, ebpf=args.ebpf,
                                identifier={"topo": os.path.basename(topo), "demands": os.path.basename(demands),
                                            "ebpf": args.ebpf, "maxseg": -1})
                #except Exception as e:
                #    lg.error("Exception %s in the graph generation...
                    #    Skipping...\n" % e)
                #    lg.error(str(e))
                #    continue
            else:
                lg.error("******* Error %s processing graphs '%s' *******\n" % (err, os.path.basename(topo)))
