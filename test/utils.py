import argparse
from scapy.all import *
from threading import Thread
import sys


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

    send(IPv6(src=src, dst=dst, tc=3) / TCP(sport=int(src_port), dport=int(dst_port), flags='A'), verbose=False)
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


utils = {
    send_tcp_ecn_pkt.__name__: send_tcp_ecn_pkt,
    send_pkt.__name__: send_pkt,
}

if __name__ == '__main__':
    args = parse_args()
    utils[args.name](*args.args)
