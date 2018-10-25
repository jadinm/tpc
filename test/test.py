import unittest
from mininet.log import lg

from ipmininet.utils import realIntfList

from examples.albilene import Albilene
from reroutemininet.net import ReroutingNet
from sricmp_dissector import *
from utils import send_tcp_ecn_pkt


class TestSRRouted(unittest.TestCase):
    """
    Test the SRRerouted daemon

    :cvar log_dir: The directory for logs of daemons started during tests
    :cvar ovsschema: The OVSDB database schema

    :type log_dir: str
    :type ovsschema: dict
    """

    log_dir = os.path.join(os.getcwd(), "test-logs")
    ovsschema = {}

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
                     "cwd": os.path.join(self.log_dir, self.test_trigger_ecn_marking.__name__)}
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
            out = net["client"].cmd(cmd)
            lg.info("Correct ICMP packet received\n")
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
        except ValueError as e:
            self.assertFalse(True, msg="Packet received could not be parsed: %s" % str(e))

    def test_trigger_ecn_marking_with_initial_srh(self):
        """
        This function tests that packets ecn marked will trigger the SRRouted daemon
        and it will reply with a well-formed ICMP. The trigger packet contains an SRH
        and so, this SRH should be present in the ICMP.
        """
        # TODO


class TestSRICMP(unittest.TestCase):

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
        # TODO


def launch_all_tests(args, ovsschema):
    lg.info("Starting testing of SRRouted daemon\n")
    TestSRRouted.log_dir = args.log_dir
    TestSRRouted.ovsschema = ovsschema

    suite = unittest.TestLoader().loadTestsFromTestCase(TestSRRouted)
    unittest.TextTestRunner().run(suite)

    lg.info("\nStarting testing of kernel reaction to SR-ICMPs\n")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSRICMP)
    unittest.TextTestRunner().run(suite)

    lg.info("Tests are finished\n")
