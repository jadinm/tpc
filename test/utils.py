import argparse
import json
from scapy.all import *
from threading import Thread

from sricmp_dissector import SRICMPv6, SRICMPIPerror6


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', help='Util function to execute', choices=utils.keys(), required=True)
    parser.add_argument('--args', help='Arguments for the function', nargs='+')
    return parser.parse_args()


class Sniffer(Thread):
    """Thread class to sniff packets with scapy"""

    WAIT_TIMER = 10

    def __init__(self, filter_bpf, count, timeout):
        super(Sniffer, self).__init__()
        self.timeout = timeout
        self.filter = filter_bpf
        self.count = count
        self.packets = []

    def run(self):
        self.packets = sniff(filter=self.filter, count=self.count, timeout=self.timeout)

    def start(self):
        super(Sniffer, self).start()
        time.sleep(Sniffer.WAIT_TIMER)  # Wait for sniffing to start


def tcp_ecn_pkt(src, dst, src_port, dst_port):
    """
    Generate one ECN-marked TCP ACK packet

    :param src: source ipv6 address of the packet
    :param dst: destination ipv6 address of the packet
    :param src_port: source port of the packet
    :param dst_port: destination port of the packet

    :type src: str
    :type dst: str
    :type src_port: str
    :type dst_port: str
    """
    return IPv6(src=src, dst=dst, tc=3) / TCP(sport=int(src_port), dport=int(dst_port), flags='A')


def send_tcp_ecn_pkt(src, dst, src_port, dst_port, timeout):
    """
    Send one ECN-marked TCP ACK packet and print the answer

    :param src: source ipv6 address of the packet
    :param dst: destination ipv6 address of the packet
    :param src_port: source port of the packet
    :param dst_port: destination port of the packet
    :param timeout: timeout after which we stop waiting for the reply (-1 means no timeout)

    :type src: str
    :type dst: str
    :type src_port: str
    :type dst_port: str
    :type timeout: str
    """

    timeout = int(timeout)
    timeout = timeout if timeout >= 0 else None
    t = Sniffer(filter_bpf="dst %s and not (icmp6 && ip6[40] == 135) and not (icmp6 && ip6[40] == 136)" % src,
                count=1, timeout=timeout)
    t.start()

    send(tcp_ecn_pkt(src, dst, src_port, dst_port), verbose=False)
    t.join()

    if len(t.packets) == 0:
        print("Cannot find any answer")
        sys.exit(-1)
    sys.stdout.write(str(t.packets[0][IPv6]).encode("hex"))


def send_pkt(packet):
    """
    Send one IPv6 packet

    :param packet: packet to send encoded as an hexadecimal string
    :type packet: str
    """
    ipv6 = IPv6(packet.decode("hex"))
    send(ipv6)


def sniff_trigger_icmp(src, dst, src_port, dst_port, redirect_ip, timeout, iface):
    """
    This function listens for a conneciton matching the parameters and send an SRICMPv6
    to redirect it through the redirect_ip address.

    :param src: source ipv6 address of the connection
    :param dst: destination ipv6 address of the connection
    :param src_port: source port of the connection
    :param dst_port: destination port of the connection
    :param redirect_ip: Intermediate address to force the connection through
    :param timeout: timeout of the capture (-1 means no timeout)
    :param iface: capture interface name

    :type src: str
    :type dst: str
    :type src_port: str
    :type dst_port: str
    :type redirect_ip: str
    :type timeout: str
    :type iface: str
    """
    timeout = int(timeout)
    timeout = timeout if timeout >= 0 else None

    trigger_packets = []
    def analyze(pkt):
        if pkt[IPv6].src == src and pkt[IPv6].dst == dst and pkt[TCP].sport == int(src_port)\
                and pkt[TCP].dport == int(dst_port) and len(pkt[TCP].payload) > 0:
            trigger_packets.append(pkt)
            return "The chosen packet:\n%s" % str(pkt.show(dump=True))
        else:
            return "Useless packet:\n%s" % str(pkt.show(dump=True))

    sniff(filter="tcp", timeout=timeout, prn=analyze, stop_filter=lambda pkt: len(trigger_packets) > 0, iface=iface)
    if len(trigger_packets) == 0:
        print("Cannot find any packet connection")
        sys.exit(1)
    trigger_packet = trigger_packets[0]
    packet = SRICMPIPerror6(str(trigger_packet[IPv6])[:48])

    icmp = IPv6(src=dst, dst=src) / SRICMPv6(trigger=packet) / IPv6ExtHdrSegmentRouting(addresses=[dst, redirect_ip])
    send(icmp)
    print("Sent ICMP:\n%s\n%s" % (icmp.show2(dump=True), str(icmp).encode("hex")))


def tcp_server(port):
    """
    This function listens on a port, accept a single connection and read sent data

    :param port: the listening port
    :type port: str
    """
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.bind(('::', int(port)))

    s.listen(1)
    conn, addr = s.accept()
    print("Connection established")
    data = True
    while data:
        data = conn.recv(1000)
        if data:
            print("Read '%s'" % str(data))
    s.close()
    print("Connection closed")


def tcp_client(src, dst, src_port, dst_port, timeout):
    """
    This function performs three actions with a waiting time after each step
      1. Establish a connection
      2. Send one packet (of 100 characters)
    The sent packets are captured and printed.

    :param src: source ipv6 address of the connection
    :param dst: destination ipv6 address of the connection
    :param src_port: source port of the connection
    :param dst_port: destination port of the connection
    :param timeout: waiting time in seconds after each step (-1 means no timeout)

    :type src: str
    :type dst: str
    :type src_port: str
    :type dst_port: str
    :type timeout: str
    """
    timeout = int(timeout)
    timeout = timeout if timeout >= 0 else None

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((src, int(src_port)))
    s.connect((dst, int(dst_port)))

    t = Sniffer(filter_bpf="ip6", count=0, timeout=4*timeout)
    debug_thread = Sniffer(filter_bpf="dst %s and (icmp6 && ip6[40] == 5)" % src,
                           count=1, timeout=3 * timeout)
    t.start()
    debug_thread.start()

    time.sleep(timeout)
    s.send("Hello" * 20)
    time.sleep(timeout)
    s.close()
    time.sleep(timeout)

    t.join()
    if len(t.packets) == 0:
        print("No TCP packet sent")
        sys.exit(1)
    hex_packets = json.dumps([str(p[IPv6]).encode("hex") for p in t.packets])
    sys.stdout.write(hex_packets)

    debug_thread.join()
    if len(debug_thread.packets) == 0:
        print("No SRICMPv6 packet received")
        sys.exit(1)
    hex_packets = str(debug_thread.packets[0][IPv6]).encode("hex")
    sys.stderr.write(hex_packets)


utils = {
    send_tcp_ecn_pkt.__name__: send_tcp_ecn_pkt,
    send_pkt.__name__: send_pkt,
    tcp_client.__name__: tcp_client,
    tcp_server.__name__: tcp_server,
    sniff_trigger_icmp.__name__: sniff_trigger_icmp,
}

if __name__ == '__main__':
    args = parse_args()
    utils[args.name](*args.args)
