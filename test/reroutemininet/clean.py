
from ipmininet.clean import cleanup as ip_clean, killprocs


def cleanup(level='info'):
    ip_clean(level=level)
    killprocs(['"^sr-"', '"^named"', '"^ovsdb"'])
