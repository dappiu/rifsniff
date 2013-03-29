# RIfSniff #
### RIfSniff is a Remote Interface Sniffer ###

1. Start the `rifsniff_collect.py` collector script on a remote target system choosing an interface to sniff on.

2. Start the `rifsniff_receive.py` receiver script on your local system specifying the host address on which the collector is running.

Packets are sniffed by the collector script, encapsulated on TCP packets and sent through the wire. The receiver script writes the TCP offload (the original packet) on a local TUN/TAP interface. Now you can start your preferred packet sniffer (e.g.: tcpdump, wireshark...) and attach it to the TUN/TAP interface and see packets flowing as if they've been sniffed on the remote interface.

RIfSniff uses native libpcap wrapped by pylibpcap to do packet sniffing.
You'll need the tun module on the system running the receiver.
You'll most likely need administrative rights to start both the collector and the receiver.



Davide Rossi
