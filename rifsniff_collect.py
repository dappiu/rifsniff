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
import logging
import argparse
import multiprocessing
from multiprocessing.reduction import reduce_handle
from multiprocessing.reduction import rebuild_handle
from binascii import hexlify

from rifsniff import proto, utils


VERSION = '0.1'

log = logging.getLogger()


def configure_logger(log):

    log.setLevel(logging.DEBUG)

    stream = logging.StreamHandler()
    stream_fmt = logging.Formatter('[%(process)d %(levelname)s] %(message)s')
    stream.setFormatter(stream_fmt)
    stream.setLevel(logging.DEBUG)

    log.addHandler(stream)


def serve_client(pipe):

    client_handle = pipe.recv()

    sockfd = rebuild_handle(client_handle)
    client_socket = socket.fromfd(sockfd, socket.AF_INET, socket.SOCK_STREAM)

    client_info = {'ip': client_socket.getpeername()[0],
                   'port': client_socket.getpeername()[1]}

    # Adding connection information (peer address:port) to logging records
    log = logging.LoggerAdapter(logging.getLogger(), client_info)
    new_log_fmt = logging.Formatter('[%(process)d %(levelname)s] \
<%(ip)s:%(port)s> %(message)s')
    logging.getLogger().handlers[0].setFormatter(new_log_fmt)

    try:
        if proto.check_protocol_version(client_socket):
            log.info('protocol versions match [%s]' %
                     (hexlify(proto.PROTOVERSION)))

        cmd = proto.recv_cmd(client_socket)

        if cmd == proto.CMD_LIST:
            log.info('client requested list of interfaces available for capture')

            devs = pcap.findalldevs()
            sentbytes = proto.send_pyobj(devs, client_socket)
            log.debug('interface list sent: %d device[s], %d bytes'
                      % (len(devs), sentbytes))

        elif cmd == proto.CMD_SNIFF:
            log.info('client wants to sniff packets on a device')
            log.debug('reading capture session options')

            dev, snaplen, bpf = proto.recv_capture_opts(client_socket)

            log.info('dev: <%s>, snaplen: <%d>, bpf: <%s>' % (dev, int(snaplen), bpf))

            p = pcap.pcapObject()
            net, mask = pcap.lookupnet(dev)
            log.info('pcap lookupnet reported <%s>:<%s>' % (pcap.ntoa(net),
                                                            pcap.ntoa(mask)))

            sentbytes = proto.send_cmd(proto.RESP_OK, client_socket)
            p.open_live(dev, 1600, 0, 100)
#            p.setfilter(string.join(sys.argv[2:],' '), 0, 0)

            while True:
                (pktlen, data, timestamp) = p.next()

                log.debug('Sniffed packet of len %d, in time %s: [%s]' %
                          (pktlen, str(timestamp), str(data)))

                sentbytes = proto.send_packet(pktlen, data, client_socket)
                if sentbytes != pktlen:
                    log.warning('sentbytes not equals pktlen')

        else:
            log.error('received an unknown command: %s' % cmd)
            raise RuntimeError('client sent an unknown command byte: %s' % cmd)

    finally:
        log.info('shutting down connection')
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()

    return 0


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

    if args.list_compact or args.list:
        try:
            devs = pcap.findalldevs()

            if not devs:
                log.warn('No device available for capture')
                log.warn('Try running the program with higher permissions (e.g.: sudo)')
            elif args.list_compact:
                log.info('Listing names of devices available for capture')
                for dev in devs:
                    log.info(dev[0])
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

            proc = multiprocessing.Process(target=serve_client, args=(pipe_r,))
            proc.start()

            client_handle = reduce_handle(client.fileno())
            pipe_w.send(client_handle)
    finally:
        logging.shutdown()

    sys.exit(0)


if __name__ == '__main__':
    main()
