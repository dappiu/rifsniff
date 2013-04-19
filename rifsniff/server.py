# -*- coding: utf-8 -*-
"""
RIfSniff Server class and utils

@author: dappiu

"""
import os
import pcap
# import signal
import socket
import logging
import multiprocessing

from multiprocessing.reduction import rebuild_handle
from datetime import datetime
from binascii import hexlify

from rifsniff.proto import RIfSniffServerSocket, PROTOVERSION, \
    CMD_LIST, CMD_SNIFF


class Sniffer:
    """Wrapper class for pcapObject packet sniffer"""

    @property
    def dev(self):
        """Returns the device name"""
        return self._dev

    @property
    def network_addr(self):
        """Returns a string describing the network address of the device"""

        return self._net

    @property
    def network_mask(self):
        """Returns a string describing the network mask of the device"""

        return self._mask

    def __init__(self, dev, snaplen, bpf=None, promisc=0, monitor=0):

        self._dev = dev
        self.snaplen = snaplen
        self.bpf = bpf
        self.promisc = int(promisc)
        self.monitor = int(monitor)

        self.p = pcap.pcapObject()

        net, mask = pcap.lookupnet(dev)
        self._net = pcap.ntoa(net)
        self._mask = pcap.ntoa(mask)

    def __enter__(self):
        """Begins the packet capture process"""

        self.p.open_live(self.dev, self.snaplen, self.promisc, 100)

        return self.p

    def __exit__(self, typ, val, tb):
        import traceback
        traceback.print_exception(typ, val, tb)

    def packet_iterator(self):
        return self.__enter__()


class RemoteInterfaceSniffer(multiprocessing.Process):
    """Sniff packets from a local interface and send them to its client"""

    @property
    def available_devices(self):

        if self.pcap_devs is None:
            self.pcap_devs = pcap.findalldevs()

        return self.pcap_devs

    def __init__(self, pipe):

        super(RemoteInterfaceSniffer, self).__init__()

        self._pipe = pipe
        self._sockfd = None
        self.sock = None
        self.peer_addr = None
        self.pcap_devs = None
        self.log = None

    def get_custom_logger(self):
        """Includes client address and port on log messages"""

        if self.peer_addr:
            peer_dict = {'ip': self.peer_addr[0], 'port': self.peer_addr[1]}

            log = logging.LoggerAdapter(logging.getLogger(), peer_dict)

            custom_fmt = logging.Formatter('[%(process)d %(levelname)s] '
                                           '<%(ip)s:%(port)s> %(message)s')
            logging.getLogger().handlers[0].setFormatter(custom_fmt)

            return log
        else:

            return logging.getLogger()

    def send_pcap_devices(self):
        """Send the list of available devices for pcap capture to the client"""

        self.log.info('Sending list of devices available for pcap capture.')

        devs = pcap.findalldevs()
        sentbytes = self.sock.send_pyobj(devs)

        self.log.debug('Sent device list to the client [%d bytes]'
                  % (sentbytes,))

    def capture_and_send_loop(self, sniffer):
        """Capture packets on chosen interface and sends them to the client"""

        self.log.info('Starting capture/send main loop')

        with sniffer as sniff:
            while True:
                (pktlen, data, timestamp) = sniff.next()

                dt = datetime.fromtimestamp(timestamp)
                self.log.debug('[%s] %d bytes packet sniffed from %s'
                               % (dt.ctime(), pktlen, sniffer.dev))

                sentbytes = self.sock.send_packet(pktlen, data)
                if sentbytes != pktlen:
                    self.log.warning('sentbytes not equals pktlen')

    def terminate(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        os._exit()

    def run(self):

        client_handle = self._pipe.recv()
        self.sockfd = rebuild_handle(client_handle)

        self.sock = RIfSniffServerSocket(self.sockfd)

        self.peer_addr = (self.sock.getpeername()[0],
                          self.sock.getpeername()[1])

        self.log = self.get_custom_logger()

        if not self.sock.check_proto_version():
            self.terminate()

        self.log.info('protocol versions match [%s]'
                      % (hexlify(PROTOVERSION),))

        cmd, payload = self.sock.recv_cmd()
        if cmd == CMD_LIST:
            self.send_pcap_devices()

        elif cmd == CMD_SNIFF:
            dev, snaplen, bpf, promisc, monitor = self.sock.recv_capture_opts()

            sniffer = Sniffer(dev, snaplen, bpf, promisc, monitor)
            self.capture_and_send_loop(sniffer)

        else:
            self.log.error('Unknown command received: %s' % cmd)
            self.terminate()
