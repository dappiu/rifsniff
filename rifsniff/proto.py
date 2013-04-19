# -*- coding: utf-8 -*-
"""
RIfSniff Protocol methods.

Data with an expected length (like plain ints or char) is directly written
to the socket and read from the other end accordingly. Variable length data is
preceded by a fixed size short integer indicating the size.

@author: dappiu@gmail.com

"""
import socket

from struct import calcsize, pack, unpack
from cPickle import dumps, loads
from binascii import hexlify

PROTOVERSION = '\x00\x00\x01\x00'
PROTOVER_FMT = '<L'

LEN_FMT = '!H'
INT_FMT = '!I'
STR_FMT = '!%ds'

CMD_FMT = 'c'
CMD_SNIFF = 'S'
CMD_LIST = 'L'
RESP_OK = 'O'
RESP_KO = 'K'
RESP_KO_PAYLOAD = 'P'
RESP_WARN_PAYLOAD = 'W'


class RIfSniffSocket(socket.socket):

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0,
                 _sock=None):
        super(RIfSniffSocket, self).__init__(family, type, proto, _sock)

    def _recvall(self, nbytes):
        """Ensures to receive the required amount of data from socket buffers"""

        buf = ''

        while len(buf) < nbytes:
            data = self.recv(nbytes - len(buf))
            if data == '':
                raise RuntimeError('socket connection broken')
            buf = buf + data

        return buf

    def _sendall(self, msg):
        """Ensures that all data are delivered to socket buffers"""

        totalsent = 0

        while totalsent < len(msg):
            sent = self.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError('socket connection broken')
            totalsent = totalsent + sent

        return totalsent

    def check_proto_version(self):
        """Sends local and reads remote protocol versions for comparison"""

        packed_len = pack(LEN_FMT, calcsize(PROTOVER_FMT))
        sentbytes = self._sendall(packed_len)
        assert sentbytes == calcsize(LEN_FMT)

        sentbytes = self._sendall(PROTOVERSION)
        assert sentbytes == calcsize(PROTOVER_FMT)

        protover_length = self._recvall(calcsize(LEN_FMT))
        protover_length = unpack(LEN_FMT, protover_length)[0]
        assert protover_length == calcsize(PROTOVER_FMT)

        protoversion = self._recvall(protover_length)
        if PROTOVERSION != protoversion:
            raise RuntimeError('protocol version mismatch: local %s != %s remote' %
                               (hexlify(PROTOVERSION), hexlify(protoversion)))

        return True

    def send_cmd(self, cmd, payload=None):
        """Encode and send a CMD option to the socket"""

        sentbytes = self._sendall(pack(CMD_FMT, cmd))
        if payload:
            self.send_string(payload)

        return sentbytes

    def recv_cmd(self):
        """Reads a binary encoded CMD option from the socket"""

        cmd = self._recvall(calcsize(CMD_FMT))

        payload = None

        if cmd in (RESP_KO_PAYLOAD, RESP_WARN_PAYLOAD):
            payload = self.recv_string()

        return unpack(CMD_FMT, cmd)[0], payload

    def send_int(self, integer):
        """Encode an integer in binary form and sends it to the socket"""

        # packing and sending integer
        packed_int = pack(INT_FMT, integer)
        sentbytes = self._sendall(packed_int)

        return sentbytes

    def recv_int(self):
        """Receive a fixed size binary integer from the socket"""

        # reading integer bytes
        int_data = self._recvall(calcsize(INT_FMT))

        return unpack(INT_FMT, int_data)[0]

    def send_string(self, data):
        """Send string length and string data to the socket in binary coding"""

        data_fmt = STR_FMT % len(data)

        # sending data len packed on a short int
        packed_len = pack(LEN_FMT, calcsize(data_fmt))
        sentbytes = self._sendall(packed_len)

        # sending binary-packed data
        packed_data = pack(data_fmt, data)
        sentbytes = self._sendall(packed_data)

        return sentbytes

    def recv_string(self):
        """Read consequently a binary-packed string length and string data
        from the socket"""

        # reading and unpacking length of the data that will follow
        data_len = self._recvall(calcsize(LEN_FMT))
        data_len = unpack(LEN_FMT, data_len)[0]

        # reading packed-data
        packed_data = self._recvall(data_len)

        # unpacking data
        data_fmt = STR_FMT % data_len

        return unpack(data_fmt, packed_data)[0]

    def send_pyobj(self, obj):
        """Encode a Python obj with pickle and sends it as a string to the socket"""

        pickled = dumps(obj, protocol=2)

        return self.send_string(pickled)

    def recv_pyobj(self):
        """Reads a pickled obj from socket and returns it after de-pickling"""

        pickled = self.recv_string()

        return loads(pickled)


class RIfSniffServerSocket(RIfSniffSocket):

    def __init__(self, fd):

        sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
        super(RIfSniffServerSocket, self).__init__(_sock=sock)

    def recv_capture_opts(self):

        dev = self.recv_string()

        snaplen = self.recv_int()

        bpf = self.recv_string()

        promisc = bool(self.recv_int())

        monitor = bool(self.recv_int())

        return dev, snaplen, bpf, promisc, monitor

    def send_packet(self, packet_len, packet_data):

        data_fmt = STR_FMT % packet_len

        # sending data len packed on a short int
        packed_len = pack(LEN_FMT, calcsize(data_fmt))
        sentbytes = self._sendall(packed_len)

        # sending data binary-packed
        packed_data = pack(data_fmt, packet_data)
        sentbytes = self._sendall(packed_data)

        return sentbytes


class RIfSniffClientSocket(RIfSniffSocket):

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0,
                 _sock=None):

        super(RIfSniffClientSocket, self).__init__(family, type, proto, _sock)

    def send_capture_opts(self, dev, snaplen, bpf, promisc, monitor):

        sentbytes = self.send_string(dev)

        sentbytes = sentbytes + self.send_int(snaplen)

        sentbytes = sentbytes + self.send_string(bpf)

        sentbytes = sentbytes + self.send_int(int(promisc))

        sentbytes = sentbytes + self.send_int(int(monitor))

        return sentbytes

    def recv_packet(self, sock):
        # reading and unpacking length of the packet
        pkt_len = self._recvall(calcsize(LEN_FMT))
        pkt_len = unpack(LEN_FMT, pkt_len)[0]

        # reading packed-data
        packed_data = self._recvall(pkt_len)

        # unpacking data
        data_fmt = STR_FMT % pkt_len

        return pkt_len, unpack(data_fmt, packed_data)[0]
