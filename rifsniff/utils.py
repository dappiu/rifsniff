# -*- coding: utf-8 -*-

import logging

log = logging.getLogger()


def print_device_description(dev):
    """Print device description as returned by python-pcap findalldev()"""

    name, desc, addrs, flags = dev

    log.info('%s: description=%s, flags=%s' % (name, desc, flags))
    if not addrs:
        log.info('\tNo addresses')
    else:
        for (addr, netmask, broadcast, dstaddr) in addrs:
            log.info('\taddr [%s] netmask [%s] broadcast [%s] dstaddr [%s]' %
                     (addr, netmask, broadcast, dstaddr))

def print_device_list(devs):
    """Print device names from the list returned by pcap"""

    for dev in devs:
        log.info(dev[0])
