import os

from ipmininet.clean import cleanup as ip_clean, killprocs
from reroutemininet.config import SRLocalCtrl


def cleanup(level='info'):
    ip_clean(level=level)
    killprocs(['"^sr-"', '"^named"', '"^ovsdb"', '^lighttpd', '^bpftool'])

    path = SRLocalCtrl.ebpf_load_path("")
    for root, dirs, files in os.walk(os.path.dirname(path)):
        for file_name in files:
            if os.path.basename(path) in file_name:
                print("Cleaning %s" % file_name)
                os.unlink(os.path.join(root, file_name))
