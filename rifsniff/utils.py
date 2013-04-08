# -*- coding: utf-8 -*-

import logging

log = logging.getLogger()


def print_device_description(dev):

    name, desc, addrs, flags = dev

    log.info('%s: description=%s, flags=%s' % (name, desc, flags))
    if not addrs:
        log.info('\tNo addresses')
    else:
        for (addr, netmask, broadcast, dstaddr) in addrs:
            log.info('\taddr [%s] netmask [%s] broadcast [%s] dstaddr [%s]' %
                     (addr, netmask, broadcast, dstaddr))
