#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
RIfSniff Packets Collector

Sniffs packets on a target interface, sending them through the wire to
a `rifsniff_receive` instance listening.

@author: dappiu@gmail.com
"""
import sys
import pcap
import socket
import logging
import argparse
import multiprocessing
from multiprocessing.reduction import reduce_handle
from multiprocessing.reduction import rebuild_handle
from binascii import hexlify

import rifsniff_proto

VERSION = '0.1'

log = logging.getLogger()


def configure_logger(log):
    log.setLevel(logging.DEBUG)
    stream = logging.StreamHandler()
    stream_fmt = logging.Formatter('[%(process)d] <%(levelname)s> %(message)s')
    stream.setFormatter(stream_fmt)
    stream.setLevel(logging.DEBUG)
    log.addHandler(stream)


def print_device_description(dev):

    name, desc, addrs, flags = dev

    print('%s: description=%s, flags=%s' % (name, desc, flags))
    if not addrs:
        print('\tNo addresses')
    else:
        for (addr, netmask, broadcast, dstaddr) in addrs:
            print('\taddr [%s] netmask [%s] broadcast [%s] dstaddr [%s]' %
                  (addr, netmask, broadcast, dstaddr))


def serve_client(pipe):
    client_handle = pipe.recv()
    sockfd = rebuild_handle(client_handle)
    client_socket = socket.fromfd(sockfd, socket.AF_INET, socket.SOCK_STREAM)

    try:
        if rifsniff_proto.check_protocol_version(client_socket):
            log.info('Protocol versions match [%s]' %
                     (hexlify(rifsniff_proto.PROTOVERSION)))

        cmd = rifsniff_proto.recv_cmd(client_socket)
        if cmd == rifsniff_proto.CMD_LIST:
            devs = pcap.findalldevs()
            sentbytes = rifsniff_proto.send_pyobj(devs, client_socket)

    finally:
        client_socket.close()
    return 0


def main():
    configure_logger(log)

    log.info('This is RIfSniff v%s' % VERSION)

    parser = argparse.ArgumentParser(description='RIfSniff Packet Collector',
        epilog='Try using it with `sudo` if --list shows no available interfaces')
    parser.VERSION = VERSION
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('-l', '--list', action='store_true',
                        help='List local interfaces available for packet capture')
    parser.add_argument('-c', '--list-compact', action='store_true',
                        help='List interface names only, no description')
    parser.add_argument('-a', '--address', type=str, default='0.0.0.0',
                        help='Address for inbound connection (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=6384,
                        help='Port for inbound connection (default: 6384)')
    args = parser.parse_args()

    if args.list_compact or args.list:
        try:
            devs = pcap.findalldevs()
            if not devs:
                log.warn('No device available for capture')
                log.warn('Try running the program with higher permissions (e.g.: sudo)')
            elif args.list_compact:
                log.info('Listing names of devices available for capture')
                for dev in devs:
                    print(dev[0])
            else:
                log.info('Listing devices available for capture')
                print_device_description(dev)
        finally:
            log.info('Exiting...')
            sys.exit(0)

    server_addr = (args.address, args.port)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_addr)
    server_socket.listen(10)

    try:
        while True:
            client, address = server_socket.accept()

            pipe_r, pipe_w = multiprocessing.Pipe(duplex=False)

            proc = multiprocessing.Process(target=serve_client, args=(pipe_r,))
            proc.start()

            client_handle = reduce_handle(client.fileno())
            pipe_w.send(client_handle)
    finally:
        logging.shutdown()

    sys.exit(0)


if __name__ == '__main__':
    main()
