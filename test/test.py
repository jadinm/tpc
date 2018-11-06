import json
import unittest
from mininet.log import lg
from random import randint

from ipmininet.utils import realIntfList, otherIntf

from examples.albilene import Albilene
from reroutemininet.net import ReroutingNet
from sricmp_dissector import *
from utils import send_tcp_ecn_pkt, sniff_trigger_icmp, tcp_client, tcp_server


class SRNMininetTest(unittest.TestCase):
    """
    Abstraction for necessary parameters for srn test class

    :cvar log_dir: The directory for logs of daemons started during tests
    :cvar ovsschema: The OVSDB database schema

    :type log_dir: str
    :type ovsschema: dict
    """

    log_dir = os.path.join(os.getcwd(), "test-logs")
    ovsschema = {}
    handler = None

    @classmethod
    def setUpClass(cls):
        path = os.path.join(cls.log_dir, cls.__name__)
        try:
            os.makedirs(os.path.abspath(path))
        except OSError:
            pass
        cls.handler = logging.FileHandler(os.path.join(path, cls.__name__ + ".log"))
        lg.addHandler(cls.handler)

    @classmethod
    def tearDownClass(cls):
        lg.removeHandler(cls.handler)


class TestSRRouted(SRNMininetTest):
    """
    Test the SRRerouted daemon
    """

    def check_icmp(self, packet, src_ip, dst_ip, src_port, dst_port, inner_srh, srh_list):
        """
        Check that SRICMPv6 matches the parameters

        :param packet: IPv6 packet to analyze
        :type packet: Packet

        :param src_ip: source ip
        :type src_ip: str

        :param dst_ip: destination ip
        :type dst_ip: str

        :param src_port: source port
        :type src_port: int

        :param dst_port: destination port
        :type dst_port: int

        :param inner_srh: SRH that should be in the trigger packet
        :type inner_srh: IPv6ExtHdrSegmentRouting

        :param srh_list: List of possible intermediate node lists that can be in the proposed SRH of the SRICMPv6
        :type srh_list: list[list[mininet.node.Node]]
        """
        self.assertIn(SRICMPv6, packet, msg="We did not receive an SR-ICMPv6 message")
        sricmpv6 = packet[SRICMPv6]

        # ICMPv6 header
        self.assertEqual(sricmpv6.type, SRICMPv6.TYPE, msg="Incorrect SR-ICMPv6 type: actual %s - expected %s" %
                                                           (sricmpv6.type, SRICMPv6.TYPE))
        self.assertEqual(sricmpv6.code, 0, msg="Incorrect SR-ICMPv6 code: actual %s - expected %s" %
                                               (sricmpv6.code, 0))
        expected_srhidx = 48 + (len(inner_srh) if inner_srh is not None else 0)
        self.assertEqual(sricmpv6.srhidx, expected_srhidx,
                         msg="Incorrect index for the inner packet: actual %d - expected %d"
                             % (sricmpv6.srhidx, expected_srhidx))
        self.assertTrue(sricmpv6.is_valid_checksum(), msg="Invalid checksum %s" % sricmpv6.cksum)

        # IP6 packet
        ip6_trigger_packet = sricmpv6.trigger
        self.assertEqual(ip6_trigger_packet.src, src_ip,
                         msg="Incorrect source IP address: actual %s - expected %s"
                             % (ip6_trigger_packet.src, src_ip))
        self.assertEqual(ip6_trigger_packet.dst, dst_ip,
                         msg="Incorrect destination IP address: actual %s - expected %s"
                             % (ip6_trigger_packet.dst, dst_ip))
        self.assertEqual(ip6_trigger_packet.nh, 6, msg="Next header is not TCP: actual %d - expected %d"
                                                       % (ip6_trigger_packet.nh, 6))

        # Inner SRH
        if inner_srh is None:
            self.assertNotIn(IPv6ExtHdrSegmentRouting, ip6_trigger_packet,
                             msg="No SRH was sent in the packet so no SRH should be in the copy inside the ICMP")
        else:
            pass  # TODO Check that addresses are matching

        # TCP first 8-bytes
        tcp_trigger_packet = ip6_trigger_packet[TCPerror]
        self.assertEqual(tcp_trigger_packet.sport, src_port,
                         msg="Incorrect source port: actual %s - expected %s"
                             % (tcp_trigger_packet.sport, src_port))
        self.assertEqual(tcp_trigger_packet.dport, dst_port,
                         msg="Incorrect destination port: actual %s - expected %s"
                             % (tcp_trigger_packet.dport, dst_port))
        self.assertEqual(tcp_trigger_packet.seq, 0,
                         msg="Incorrect segment number: actual %s - expected %s" % (tcp_trigger_packet.seq, 0))

        # SRH
        srh = sricmpv6.payload
        self.assertIn(IPv6ExtHdrSegmentRouting, srh, msg="Cannot reconstruct Segment Routing Header from %s" % str(srh))
        self.assertEqual(srh.type, 4, msg="Extension Routing header is not Segment Routing type:"
                                          " actual %d - expected %d" % (srh.type, 4))
        self.assertEqual(srh.lastentry, srh.segleft,
                         msg="IPv6 Segment Routing Header should not have any 'consumed' segment:"
                             " srh.lastentry %d - srh.segleft %d"
                             % (srh.lastentry, srh.segleft))
        self.assertEqual(srh.segleft + 1, len(srh.addresses),
                         msg="The SRH should not have already consumed segments or fewer segments:"
                             " actual %d - excepted %d"
                             % (srh.segleft + 1, len(srh.addresses)))

        matching_srh = False
        for possible_srh in srh_list:
            if len(possible_srh) != len(srh.addresses):
                continue
            i = 0
            for node in possible_srh:
                found_ip = False
                for itf in node.intfList():
                    for ip6 in itf.ip6s(exclude_lls=True):
                        if ip6.ip.compressed == srh.addresses[i]:
                            found_ip = True
                            break
                    if found_ip:
                        break
                if not found_ip:
                    break
                matching_srh = found_ip
                i += 0
            if matching_srh:
                break
        self.assertTrue(matching_srh, msg="The Segment List %s is not matching any possible SRH %s"
                                          % (srh.addresses, srh_list))

    def test_trigger_ecn_marking(self):
        """
        This function tests that packets ecn marked will trigger the SRRouted daemon
        and it will reply with a well-formed ICMP.
        """
        topo_args = {"schema_tables": self.ovsschema["tables"],
                     "cwd": os.path.join(self.log_dir, type(self).__name__, self.test_trigger_ecn_marking.__name__)}
        net = ReroutingNet(topo=Albilene(always_redirect=True, **topo_args), static_routing=True)
        try:
            net.start()

            # Wait for the OVSDB to be executed
            lg.info("Waiting for sr-ctrl to pre-compute paths\n")
            time.sleep(10)  # TODO Look in OVSDB table that everything is setup

            lg.info("Sending ECN marked packet\n")
            src_ip = realIntfList(net["client"])[0].ip6
            src_port = 6000
            dst_ip = realIntfList(net["server"])[0].ip6
            dst_port = 80
            cmd = ["python", os.path.join(os.path.dirname(__file__), "utils.py"),
                   "--name", send_tcp_ecn_pkt.__name__, "--args", src_ip, dst_ip, str(src_port), str(dst_port), "10"]
            out, err, exitcode = net["client"].pexec(cmd)
            self.assertEqual(exitcode, 0, msg="The triggering of an ICMP failed:\nCommand '%s' returned %d\n"
                                              "Output: %s\nError: %s" % (" ".join(cmd), exitcode, out, err))
        finally:
            net.stop()

        self.assertNotEqual(out, 'None', msg="We did not receive anything from the other host")
        try:
            packet_bytes = out.decode("hex")
        except TypeError:
            self.assertFalse(True, msg="The output of %s was not the packet\n%s" % (cmd, out))
            return

        try:
            packet = IPv6(packet_bytes)
            self.assertEqual(packet.nh, 58, msg="We did not received an ICMPv6 message from SRRouting\n"
                                                "binary=%s\nipv6 packet=%s" % (out, packet.show(dump=True)))
            self.check_icmp(packet, src_ip, dst_ip, src_port, dst_port, None,
                            [[net["server"]],
                             [net["server"], net["B"]]])
            lg.info("Correct ICMP packet received\n")
        except ValueError as e:
            self.assertFalse(True, msg="Packet received could not be parsed: %s" % str(e))

    def test_trigger_ecn_marking_with_initial_srh(self):
        """
        This function tests that packets ecn marked will trigger the SRRouted daemon
        and it will reply with a well-formed ICMP. The trigger packet contains an SRH
        and so, this SRH should be present in the ICMP.
        """
        # TODO


class TestSRICMP(SRNMininetTest):
    """
    Test the ICMP format and the kernel reaction to it
    """

    def test_sricmp_dissector(self):
        """
        Check the dissector SRICMPv6 behavior:
            - Generation of packets
            - Inference of upper layers
            - Dissection of generated packets
        """

        try:
            IPv6() / SRICMPv6() / IPv6ExtHdrSegmentRouting()
        except Exception as e:
            self.assertFalse(True, msg="Cannot create an SR ICMP packet:\n%s" % str(e))

        try:
            IPv6(str(IPv6() / SRICMPv6() / Raw(str(IPv6ExtHdrSegmentRouting()))))
        except Exception as e:
            self.assertFalse(True, msg="Cannot dissect a generated ICMP packet:\n%s" % str(e))

    def test_kernel_receive(self):
        """
        Check that the kernel can parse the ICMP and change set the SRH of the connection socket
        """
        topo_args = {"schema_tables": self.ovsschema["tables"],
                     "cwd": os.path.join(self.log_dir, type(self).__name__, self.test_kernel_receive.__name__)}
        net = ReroutingNet(topo=Albilene(**topo_args), static_routing=True)
        try:
            net.start()

            lg.info("Starting TCP connection and forge an SR6ICMP\n")
            src_ip = realIntfList(net["client"])[0].ip6
            src_port = randint(50000, 64000)
            dst_ip = realIntfList(net["server"])[0].ip6
            dst_port = randint(50000, 64000)
            redirect_ip = [i for i in net["D"].intf("lo").ip6s(exclude_lls=True) if i.ip.compressed != "::1"][0].ip.compressed

            capture_itf = None
            for itf in realIntfList(net["client"]):
                if otherIntf(itf).node.name == "A":
                    capture_itf = otherIntf(itf)
                    break
            self.assertIsNotNone(capture_itf, msg="Cannot find an interface to capture to")

            # Drop packets on the shortest path so that we wait for the redirection before success of the sending

            cmd = "ip6tables -A FORWARD -p tcp --destination-port {dstport} --source-port {srcport}" \
                  " --tcp-flags SYN,ACK,FIN,RST ACK -m length ! --length 0:80 -j DROP".format(dstport=dst_port,
                                                                                               srcport=src_port)
            net["B"].cmd(cmd.split(" "))
            try:
                sniff_cmd = ["python", os.path.join(os.path.dirname(__file__), "utils.py"),
                             "--name", sniff_trigger_icmp.__name__,
                             "--args", src_ip, dst_ip, str(src_port), str(dst_port), redirect_ip, "60", capture_itf.name]
                sniff_popen = net["A"].popen(sniff_cmd)

                listen_cmd = ["python", os.path.join(os.path.dirname(__file__), "utils.py"),
                              "--name", tcp_server.__name__, "--args", str(dst_port)]
                listen_popen = net["server"].popen(listen_cmd)

                time.sleep(10)  # Wait for the server to start
                client_cmd = ["python", os.path.join(os.path.dirname(__file__), "utils.py"),
                              "--name", tcp_client.__name__, "--args", src_ip, dst_ip, str(src_port), str(dst_port), "10"]
                client_popen = net["client"].popen(client_cmd)

                listen_out = listen_popen.stdout.readline()  # Wait for the client to connect to the server
                lg.debug("Client and server connected")

                # Wait for the client to finish the connection
                lg.info("Waiting for end of client program\n")
                exitcode = client_popen.wait()
                lg.debug("Client and server finished their transfer")
                client_out = client_popen.stdout.read()
                client_err = client_popen.stderr.read()
                self.assertEqual(exitcode, 0, msg="The TCP client that should have been rerouted failed:\n"
                                                  "Command '%s' returned %d\nOutput: %s\nError: %s"
                                                  % (" ".join(client_cmd), exitcode, client_out, client_err))
            finally:
                cmd = "ip6tables -A FORWARD -p tcp --destination-port {dstport} --source-port {srcport}" \
                      " --tcp-flags SYN,ACK,FIN,RST ACK -m length ! --length 0:100 -j DROP".format(dstport=dst_port,
                                                                                                   srcport=src_port)
                net["B"].cmd(cmd.split(" "))

            # Wait for the ICMP to be sent
            lg.info("Waiting for ICMP forging\n")
            exitcode = sniff_popen.poll()
            if exitcode is None:
                sniff_popen.kill()
            sniff_out = sniff_popen.stdout.read()
            sniff_err = sniff_popen.stdout.read()
            self.assertEqual(exitcode, 0, msg="The ICMP generator should have stopped correctly "
                                              "if the TCP client has finished without error\n"
                                              "Command '%s' returned %s\nOutput: %s\nError: %s"
                                              % (" ".join(sniff_cmd), exitcode, sniff_out, sniff_err))

            exitcode = listen_popen.poll()
            if exitcode is None:
                listen_popen.kill()
                exitcode = listen_popen.wait(timeout=1)
            listen_out += listen_popen.stdout.read()
            listen_err = listen_popen.stderr.read()
            self.assertEqual(exitcode, 0, msg="The TCP server should have stopped correctly "
                                              "if the TCP client has closed the connection\n"
                                              "Command '%s' returned %s\nOutput: %s\nError: %s"
                                              % (" ".join(listen_cmd), exitcode, listen_out, listen_err))
        finally:
            net.stop()

        packets = json.loads(client_out)
        rerouted_packet = None
        for packet_str in packets:
            packet = IPv6(packet_str.decode("hex"))
            if IPv6ExtHdrSegmentRouting in packet:
                rerouted_packet = packet

        packets_str = ""
        for packet in packets:
            packets_str += IPv6(packet.decode("hex")).show(dump=True) + "\n"
        self.assertIsNotNone(rerouted_packet, msg="No packet was rerouted upon reception of the SR6ICMP:\n%s\n"
                                                  "icmp received on client:\n%s\nsniffer output:\n%s"
                                                  "\nserver output:\n%s"
                                                  % (packets_str, IPv6(client_err.decode("hex")).show(dump=True),
                                                     sniff_out, listen_out))

        srh = rerouted_packet[IPv6ExtHdrSegmentRouting]
        self.assertEqual(srh.addresses, [dst_ip, redirect_ip],
                         msg="The SRH has unexpected addresses: actual %s - expected %s"
                             % (srh.addresses, [dst_ip, redirect_ip]))
        lg.info("Redirection of the connection was successful\n")


def launch_all_tests(args, ovsschema):
    lg.info("Starting testing of SRRouted daemon\n")
    TestSRRouted.log_dir = args.log_dir
    TestSRRouted.ovsschema = ovsschema

    suite = unittest.TestLoader().loadTestsFromTestCase(TestSRRouted)
    unittest.TextTestRunner().run(suite)

    lg.info("\nStarting testing of kernel reaction to SR-ICMPs\n")
    TestSRICMP.log_dir = args.log_dir
    TestSRICMP.ovsschema = ovsschema

    suite = unittest.TestLoader().loadTestsFromTestCase(TestSRICMP)
    unittest.TextTestRunner().run(suite)

    lg.info("Tests are finished\n")
