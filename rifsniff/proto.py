# -*- coding: utf-8 -*-
"""
RIfSniff Protocol methods.

Data with an expected length (like plain ints or char) is directly written
to the socket and read from the other end accordingly. Variable length data is
preceded by a fixed size short integer indicating the size.

@author: dappiu@gmail.com

"""
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


def _recvall(nbytes, sock):
    """Ensures to receive the required amount of data from socket buffers"""

    buf = ''

    while len(buf) < nbytes:
        data = sock.recv(nbytes - len(buf))
        if data == '':
            raise RuntimeError('socket connection broken')
        buf = buf + data

    return buf


def _sendall(msg, sock):
    """Ensures that all data are delivered to socket buffers"""

    totalsent = 0

    while totalsent < len(msg):
        sent = sock.send(msg[totalsent:])
        if sent == 0:
            raise RuntimeError('socket connection broken')
        totalsent = totalsent + sent

    return totalsent


def check_protocol_version(sock):
    """Sends local and reads remote protocol versions for comparison"""

    packed_len = pack(LEN_FMT, calcsize(PROTOVER_FMT))
    sentbytes = _sendall(packed_len, sock)
    assert sentbytes == calcsize(LEN_FMT)

    sentbytes = _sendall(PROTOVERSION, sock)
    assert sentbytes == calcsize(PROTOVER_FMT)

    protover_length = _recvall(calcsize(LEN_FMT), sock)
    protover_length = unpack(LEN_FMT, protover_length)[0]
    assert protover_length == calcsize(PROTOVER_FMT)

    protoversion = _recvall(protover_length, sock)
    if PROTOVERSION != protoversion:
        raise RuntimeError('protocol version mismatch: local %s != %s remote' %
                           (hexlify(PROTOVERSION), hexlify(protoversion)))

    return True


def send_cmd(cmd, sock):
    """Encode and send a CMD option to the socket"""

    sentbytes = _sendall(pack(CMD_FMT, cmd), sock)

    return sentbytes


def recv_cmd(sock):
    """Reads a binary encoded CMD option from the socket"""

    cmd = _recvall(calcsize(CMD_FMT), sock)

    return unpack(CMD_FMT, cmd)[0]


def send_int(integer, sock):
    """Encode an integer in binary form and sends it to the socket"""
    # packing and sending integer
    packed_int = pack(INT_FMT, integer)
    sentbytes = _sendall(packed_int, sock)

    return sentbytes


def recv_int(sock):
    """Receive a fixed size binary integer from the socket"""

    # reading integer bytes
    int_data = _recvall(calcsize(INT_FMT), sock)

    return unpack(INT_FMT, int_data)[0]


def send_string(data, sock):
    """Send string length and string data to the socket in binary coding"""

    data_fmt = STR_FMT % len(data)

    # sending data len packed on a short int
    packed_len = pack(LEN_FMT, calcsize(data_fmt))
    sentbytes = _sendall(packed_len, sock)

    # sending data binary-packed
    packed_data = pack(data_fmt, data)
    sentbytes = _sendall(packed_data, sock)

    return sentbytes


def recv_string(sock):
    """Read consequently a binary-packed string length and string data
    from the socket"""

    # reading and unpacking length of the data that will follow
    data_len = _recvall(calcsize(LEN_FMT), sock)
    data_len = unpack(LEN_FMT, data_len)[0]

    # reading packed-data
    packed_data = _recvall(data_len, sock)

    # unpacking data
    data_fmt = STR_FMT % data_len

    return unpack(data_fmt, packed_data)[0]


def send_pyobj(obj, sock):
    """Encode a Python obj with pickle and sends it as a string to the socket"""

    pickled = dumps(obj, protocol=2)

    return send_string(pickled, sock)


def recv_pyobj(sock):
    """Reads a pickled obj from socket and returns it after de-pickling"""

    pickled = recv_string(sock)

    return loads(pickled)


def send_capture_opts(dev, snaplen, bpf, sock):

    sentbytes = send_string(dev, sock)

    sentbytes = sentbytes + send_int(snaplen, sock)

    sentbytes = sentbytes + send_string(bpf, sock)

    return sentbytes


def recv_capture_opts(sock):

    dev = recv_string(sock)

    snaplen = recv_int(sock)

    bpf = recv_string(sock)

    return dev, snaplen, bpf


def send_packet(packet_len, packet_data, sock):

    data_fmt = STR_FMT % packet_len

    # sending data len packed on a short int
    packed_len = pack(LEN_FMT, calcsize(data_fmt))
    sentbytes = _sendall(packed_len, sock)

    # sending data binary-packed
    packed_data = pack(data_fmt, packet_data)
    sentbytes = _sendall(packed_data, sock)

    return sentbytes


def recv_packet(sock):
    # reading and unpacking length of the packet
    pkt_len = _recvall(calcsize(LEN_FMT), sock)
    pkt_len = unpack(LEN_FMT, pkt_len)[0]

    # reading packed-data
    packed_data = _recvall(pkt_len, sock)

    # unpacking data
    data_fmt = STR_FMT % pkt_len

    return pkt_len, unpack(data_fmt, packed_data)[0]
