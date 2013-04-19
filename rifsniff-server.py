#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
RIfSniff Packets Collector

Sniffs packets on a target interface, sending them through the wire to
a `rifsniff_receive` instance listening.

@author: dappiu@gmail.com
"""
import pdb  # XXX: Remove
import sys
import pcap
import socket
import signal
import logging
import argparse
import multiprocessing
from multiprocessing.reduction import reduce_handle


from rifsniff import utils
from rifsniff.server import RemoteInterfaceSniffer


VERSION = '0.1'

log = logging.getLogger()


PROCLIST = []


def sighandler(signum, frame):
    log.info('RECEIVED SIGNAL: %d' % signum)
    for proc in PROCLIST:
        proc.terminate()


def configure_logger(log):

    log.setLevel(logging.DEBUG)

    stream = logging.StreamHandler()
    stream_fmt = logging.Formatter('[%(process)d %(levelname)s] %(message)s')
    stream.setFormatter(stream_fmt)
    stream.setLevel(logging.DEBUG)

    log.addHandler(stream)


def main():

    configure_logger(log)

    log.info('This is RIfSniff Collector v%s' % VERSION)

    parser = argparse.ArgumentParser(description='RIfSniff Packet Collector',
        epilog='Try using it with `sudo` if --list shows no available interfaces')

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

    signal.signal(signal.SIGINT, sighandler)

    if args.list_compact or args.list:
        try:
            devs = pcap.findalldevs()

            if not devs:
                log.warn('No device available for capture')
                log.warn('Try running the program with higher permissions (e.g.: sudo)')
            elif args.list_compact:
                log.info('Listing names of devices available for capture')
                utils.print_device_list(devs)
            else:
                log.info('Listing devices available for capture')
                for dev in devs:
                    utils.print_device_description(dev)
        finally:
            log.info('Exiting...')
            sys.exit(0)

    server_addr = (args.address, args.port)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_addr)
    server_socket.listen(10)

    try:
        while True:
            log.info('server socket listening on <%s:%d>' % server_addr)
            client, address = server_socket.accept()

            pipe_r, pipe_w = multiprocessing.Pipe(duplex=False)

            #proc = multiprocessing.Process(target=serve_client, args=(pipe_r,))
            proc = RemoteInterfaceSniffer(pipe_r)
            PROCLIST.append(proc)
            proc.start()

            client_handle = reduce_handle(client.fileno())
            pipe_w.send(client_handle)
    finally:
        logging.shutdown()

    sys.exit(0)


if __name__ == '__main__':
    main()
