#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
RIfSniff Packets Receiver

Receives packets sniffed by `rifsniff_collect` collector program. Packets
can be written on a tun/tap interface or printed to stdout in tcpdump format.

@author: dappiu@gmail.com

"""
import pdb
import pytun
import socket
import logging
import argparse
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


def main():
    parser = argparse.ArgumentParser(description='RIfSniff Packet Receiver')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('-a', '--address', type=str, default='localhost',
                        help='server (collector) address')
    parser.add_argument('-p', '--port', type=int, default=6384,
                        help='port where the collector is listening')
    args = parser.parse_args()

    server_addr = (args.address, args.port)
    client_socket = socket.create_connection(server_addr, 30)

    try:
        if rifsniff_proto.check_protocol_version(client_socket):
            log.info('Protocol versions match [%s]' %
                     (hexlify(rifsniff_proto.PROTOVERSION)))

        rifsniff_proto.send_cmd(rifsniff_proto.CMD_LIST, client_socket)

        devs = rifsniff_proto.recv_pyobj(client_socket)

        log.info('Shutting down connection')
        client_socket.shutdown(socket.SHUT_RD)
    except:
        raise
    finally:
        client_socket.close()


if __name__ == '__main__':
    main()
