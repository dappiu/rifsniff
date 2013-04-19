#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
RIfSniff Packets Receiver

Receives packets sniffed by `rifsniff_collect` collector program. Packets
can be written on a tun/tap interface or printed to stdout in tcpdump format.

@author: dappiu@gmail.com

"""
import sys
import pytun
import socket
import logging
import argparse
from binascii import hexlify

from rifsniff import utils
from rifsniff.proto import RIfSniffClientSocket, \
    PROTOVERSION, CMD_LIST, CMD_SNIFF, RESP_OK, RESP_KO

VERSION = '0.1'

log = logging.getLogger()


def configure_logger(log):

    log.setLevel(logging.DEBUG)

    stream = logging.StreamHandler()
    stream_fmt = logging.Formatter('[%(process)d] <%(levelname)s> %(message)s')
    stream.setFormatter(stream_fmt)
    stream.setLevel(logging.DEBUG)

    log.addHandler(stream)


def main():

    configure_logger(log)

    log.info('This is RIfSniff Receiver v%s' % VERSION)

    parser = argparse.ArgumentParser(description='RIfSniff Packet Receiver')

    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('-a', '--address', type=str, default='localhost',
                        help='server (collector) address')
    parser.add_argument('-p', '--port', type=int, default=6384,
                        help='port where the collector is listening')
    parser.add_argument('-L', '--list', action='store_true',
                        help=('Lists available remote interfaces (if any) '
                        'and exits'))
    parser.add_argument('-r', '--remote', type=str,
                        help='[mandatory] Remote interface name')
    parser.add_argument('-l', '--local', type=str, default='tap0',
                        help=('Name of the local virtual interface '
                        '(default: tap0)'))
    parser.add_argument('-f', '--filter', type=str, default='',
                        help=('BPF Filter to attach to remote interface '
                        '(default: none)'))
    parser.add_argument('-s', '--snaplen', type=int, default=1500,
                        help='Truncate packet at length (default: 1500)')
    parser.add_argument('-P', '--promisc', type=bool, default=False,
                        help='Put interface in promiscuos mode')
    parser.add_argument('-m', '--monitor', type=bool, default=False,
                        help='Put interface in monitor mode')
    args = parser.parse_args()

    if not args.list and not args.remote:
        log.error('Remote interface name missing. Use --remote to select\n')
        parser.print_usage()
        sys.exit(1)

    sock = RIfSniffClientSocket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)

    server_addr = (args.address, args.port)
    sock.connect(server_addr)

    log.info('connection established. sending request...')

    try:
        if sock.check_proto_version():
            log.info('protocol versions match [%s]' %
                     (hexlify(PROTOVERSION)))

        if args.list:

            sock.send_cmd(CMD_LIST)

            devs = sock.recv_pyobj()
            for dev in devs:
                utils.print_device_description(dev)
        else:

            tap = pytun.TunTapDevice(name=args.local,
                                     flags=pytun.IFF_TAP | pytun.IFF_NO_PI)
            tap.up()
            log.info('Tap device created. Attach your sniffer, if you want, '
                     'and press any key to continue...')
            raw_input()

            tap.mtu = args.snaplen

            log.debug('Tap MTU before activation is %d' % tap.mtu)

            log.info(args)
            sock.send_cmd(CMD_SNIFF)
            sock.send_capture_opts(args.remote, args.snaplen, args.filter,
                                   args.promisc, args.monitor)

            resp, payload = sock.recv_cmd()
            if resp == RESP_KO:

                log.error('Remote error')
                # receive error description and log it...
            elif resp == RESP_OK:

                log.info('Everything Ok. Preparing to receive packets from remote')

                # TODO: create another channel for packets, using the other one
                #       to exchange execution status
                while True:

                    pktlen, pkt = sock.recv_packet()

                    log.debug('%d bytes packet sniffed from %s'
                              % (pktlen, args.remote))

                    tap.write(pkt)

                    log.debug('%d bytes packet wrote into %s'
                              % (pktlen, args.local))
            else:
                log.error('Something weird happened!')

        log.info('shutting down connection')
        sock.shutdown(socket.SHUT_RD)
    except:
        sock.shutdown(socket.SHUT_RD)
        raise
    finally:
        sock.close()


if __name__ == '__main__':
    main()
