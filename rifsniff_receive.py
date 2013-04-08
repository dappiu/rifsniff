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
import subprocess  #  TODO: remove if tap.up() works
from binascii import hexlify

#import rifsniff_proto as proto
from rifsniff import proto, utils


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
                        help='Lists available remote interfaces (if any) and exits')
    parser.add_argument('-r', '--remote', type=str,
                        help='[mandatory] Remote interface name')
    parser.add_argument('-l', '--local', type=str, default='tap0',
                        help='[optional] Name of the local virtual interface (default: tap0)')
    parser.add_argument('-f', '--filter', type=str, default='',
                        help='BPF Filter to attach to remote interface (default: none)')
    parser.add_argument('-s', '--snaplen', type=int, default=1500,
                        help='Truncate packet at length (default: 1500)')
    args = parser.parse_args()

    if not args.list and not args.remote:
        log.error('remote interface name missing. use --remote switch to select\n')
        parser.print_usage()
        sys.exit(1)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(10.0)

    server_addr = (args.address, args.port)
    client_socket.connect(server_addr)

    log.info('connection established. sending request...')

    try:
        if proto.check_protocol_version(client_socket):
            log.info('protocol versions match [%s]' %
                     (hexlify(proto.PROTOVERSION)))

        if args.list:

            proto.send_cmd(proto.CMD_LIST, client_socket)

            devs = proto.recv_pyobj(client_socket)
            for dev in devs:
                utils.print_device_description(dev)
        else:

            tap = pytun.TunTapDevice(name=args.local,
                                     flags=pytun.IFF_TAP|pytun.IFF_NO_PI)
            tap.up()
            log.info('Tap device created. Attach your sniffer, if you want, \
and press any key to continue...')
            raw_input()

            tap.mtu = args.snaplen  # FIXME: Is really necessary?

            log.debug('Tap MTU before activation is %d' % tap.mtu)

#            try:
#                subprocess.check_call(['sudo', 'ifconfig', args.local, 'up'])
#            except subprocess.CalledProcessError as cpe:
#                log.warning('ifconfig failed with code %d' % (cpe.returncode))
#                log.warning('Unable to activate the tap interface. Try running \
#`ifconfig %s up` manually if the device appears created but not active.' % args.local)

            #tap.up()
            log.debug('Tap MTU after activation is %d' % tap.mtu)

            log.info(args)
            proto.send_cmd(proto.CMD_SNIFF, client_socket)
            proto.send_capture_opts(args.remote, args.snaplen, args.filter,
                                    client_socket)

            resp = proto.recv_cmd(client_socket)
            if resp == proto.RESP_KO:

                log.error('Remote error')
                # receive error description and log it...
            elif resp == proto.RESP_OK:

                log.info('Everything Ok. Preparing to receive packets from remote')

                # TODO: create another channel for packets, using the other one
                #       to exchange execution status
                while True:

                    packet_data = proto.recv_packet(client_socket)

                    log.debug('Packet received! %d bytes, [%s]'
                              % (len(packet_data), packet_data))

                    tap.write(packet_data)

                    log.debug('Packet wrote! %d bytes, [%s]'
                              % (len(packet_data), packet_data))
            else:
                log.error('Something weird happened!')

        log.info('shutting down connection')
        client_socket.shutdown(socket.SHUT_RD)
    except:
        raise
    finally:
        client_socket.close()


if __name__ == '__main__':
    main()
