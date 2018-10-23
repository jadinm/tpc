import unittest
from mininet.log import lg
from scapy.all import *

from ipmininet.utils import realIntfList

from examples.albilene import Albilene
from reroutemininet.net import ReroutingNet
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
                icmpv6 = packet[1]
                icmpv6_load = icmpv6.load.encode("hex")

                # ICMPv6 header
                idx = 0
                icmpv6_type = icmpv6_load[idx:idx+2]
                self.assertEqual(icmpv6_type, '05', msg="Incorrect SR-ICMPv6 type: actual %s - expected %s" %
                                                        (icmpv6_type, '05'))
                idx += 2*1

                icmpv6_code = icmpv6_load[idx:idx+2]
                self.assertEqual(icmpv6_code, '00', msg="Incorrect SR-ICMPv6 code: actual %s - expected %s" %
                                                        (icmpv6_code, '00'))
                idx += 2*3

                # IP6 packet
                ip6_trigger_packet = IPv6(icmpv6_load[idx:].decode("hex"))
                self.assertEqual(ip6_trigger_packet.src, src_ip, msg="Incorrect source IP address:"
                                                                     " actual %s - expected %s"
                                                                     % (ip6_trigger_packet.src, src_ip))
                self.assertEqual(ip6_trigger_packet.dst, dst_ip, msg="Incorrect destination IP address:"
                                                                     " actual %s - expected %s"
                                                                     % (ip6_trigger_packet.dst, dst_ip))
                self.assertEqual(ip6_trigger_packet.nh, 6, msg="Next header is not TCP: actual %d - expected %d"
                                                                     % (ip6_trigger_packet.nh, 6))
                idx += 2*40

                # TCP first 8-bytes
                sport = int(icmpv6_load[idx:idx+4], 16)
                self.assertEqual(sport, src_port, msg="Incorrect source port: actual %s - expected %s" % (sport, src_port))
                idx += 2*2
                dport = int(icmpv6_load[idx:idx+4], 16)
                self.assertEqual(dport, dst_port, msg="Incorrect destination port: actual %s - expected %s" % (dport, dst_port))
                idx += 2*2

                segnum = int(icmpv6_load[idx:idx+8], 16)
                self.assertEqual(segnum, 0, msg="Incorrect segment number: actual %s - expected %s" % (segnum, 0))
                idx += 2*4

                # SRH
                srh = IPv6ExtHdrRouting(icmpv6_load[idx:].decode("hex"))
                self.assertEqual(srh.type, 4, msg="Extension Routing header is not Segment Routing type:"
                                                  " actual %d - expected %d" % (srh.type, 4))
                srh_hex = hex(srh.reserved)[2:]
                if len(srh_hex) % 2 != 0:
                    srh_hex = "0" + srh_hex
                srh_first_seg = int(srh_hex[:2], 16)
                self.assertEqual(srh_first_seg, srh.segleft,
                                 msg="IPv6 Segment Routing Header should not have any 'consumed' segment:"
                                     " srh.firstseg %d - srh.segleft %d"
                                     % (srh_first_seg, srh.segleft))
                self.assertEqual(srh.len, (srh.segleft + 1) * 2,
                                 msg="IPv6 Segment Routing Header length should cover all segments (no TLV here):"
                                     " actual %d - excepted %d"
                                     % (srh.len, (srh.segleft + 1) * 2))

                for segment in srh.addresses:
                    found = False
                    for node in net:
                        for itf in net[node].intfList():
                            for ip6 in itf.ip6s(exclude_lls=True):
                                if ip6.ip.compressed == segment:
                                    found = True
                                    break
                            if found:
                                break
                        if found:
                            break
                    self.assertTrue(found, msg="The segment %s does not match any address of the nodes" % segment)

            except ValueError as e:
                self.assertFalse(True, msg="Packet received could not be parsed: %s" % str(e))

            lg.info("Correct ICMP packet received\n")
        finally:
            net.stop()

    def trigger_ecn_marking_with_initial_srh(self):
        """
        This function tests that packets ecn marked will trigger the SRRouted daemon
        and it will reply with a well-formed ICMP. The trigger packet contains an SRH
        and so, this SRH should be present in the ICMP.
        """
        # TODO


class TestSRICMP(unittest.TestCase):
    pass  # TODO Check that received ICMPs are correctly parsed


def launch_all_tests(args, ovsschema):
    lg.info("Starting testing of SRRouted daemon\n")
    TestSRRouted.log_dir = args.log_dir
    TestSRRouted.ovsschema = ovsschema

    suite = unittest.TestLoader().loadTestsFromTestCase(TestSRRouted)
    unittest.TextTestRunner().run(suite)

    lg.info("Starting testing of kernel reaction to SR-ICMPs\n")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSRICMP)
    unittest.TextTestRunner().run(suite)

    lg.info("Tests are finished\n")
