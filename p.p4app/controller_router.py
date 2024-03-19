import socket

from sniffer import sniff
from threading import Thread, Event
from p4runtime_lib.convert import *
from headers.router_cpu_metadata import RouterCPUMetadata
from scapy.all import Ether, ARP, IP, ICMP, Raw


class Interface:
    def __init__(self, mac_addr, ip_addr, mask, hello_int):
        self.ip_addr = ip_addr
        self.mask = mask
        self.hello_int = hello_int
        self.mac_addr = mac_addr
        self.neighbours = {}


class RouterController(Thread):
    def __init__(self, router, router_intfs):
        super(RouterController, self).__init__()
        self.router = router
        self.intf = router.intfs[1].name
        self.stop_event = Event()
        self.stored_packet = None
        self.intfs = []
        self.arp_table = {}

        for intf in router_intfs:
            self.intfs.append(Interface(intf[0], intf[1], intf[2], 3))

    def send(self, port: int, pkt: bytes):
        """
        Send packet to correct interface which is identified by port of switch
        :param port: Port number which corresponds to the interface of switch
        :param pkt: Packet to send
        """
        packet = Ether(pkt)
        #print(self.router.name, self.router.intfs[port].name)
        #packet.show()
        raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((self.router.intfs[port].name, 0))
        raw_socket.send(pkt)
        raw_socket.close()

    def print_arp_table(self):
        print(self.arp_table)

    def handle_arp_reply(self, pkt):
        """
        Process arp reply by adding entry of requested pair - mac address and ip address
        to data plane arp table and copy contained by controller
        :param pkt: Packet to process
        """
        # check if the entry is already in arp table
        if pkt[ARP].psrc not in self.arp_table:
            # add a pair of ip address, mac address to arp table copy stored by controller
            self.arp_table[pkt[ARP].psrc] = pkt[ARP].hwsrc

        # add a pair of ip address, mac address to arp table
        self.router.insertTableEntry(table_name='ingress_control.arp_table',
                                     match_fields={'next_hop': pkt[ARP].psrc},
                                     action_name='ingress_control.set_dmac',
                                     action_params={'mac_dest': pkt[ARP].hwsrc})

        # send back packet stored before sending arp request
        if self.stored_packet:
            self.stored_packet[Ether].dst = self.arp_table[self.stored_packet[RouterCPUMetadata].nextHop]
            self.send(1, bytes(self.stored_packet))
            self.stored_packet = None
            print(self.stored_packet)

    def send_arp_request(self, pkt):
        """
        Create arp request packet, which will be sent to port with unknown mac address
        :param pkt: Packet stored to be sent after reply will arrive
        """
        # Store packet in controller
        self.stored_packet = pkt
        self.stored_packet.show()
        # Create arp request packet
        new_packet = Ether() / RouterCPUMetadata() / ARP()

        new_packet[Ether].dst = "ff:ff:ff:ff:ff:ff"
        new_packet[Ether].src = self.intfs[pkt[RouterCPUMetadata].dstPort - 2].mac_addr
        new_packet[Ether].type = 0x80b

        new_packet[RouterCPUMetadata].fromCpu = 1
        new_packet[RouterCPUMetadata].origEthType = 0x806
        new_packet[RouterCPUMetadata].srcPort = 1
        new_packet[RouterCPUMetadata].dstPort = pkt[RouterCPUMetadata].dstPort

        new_packet[ARP].hwlen = 6
        new_packet[ARP].plen = 4
        new_packet[ARP].op = 1
        new_packet[ARP].pdst = pkt[RouterCPUMetadata].nextHop
        new_packet[ARP].hwsrc = self.intfs[pkt[RouterCPUMetadata].dstPort - 2].mac_addr
        new_packet[ARP].psrc = self.intfs[pkt[RouterCPUMetadata].dstPort - 2].ip_addr
        # Send packet to data plane
        self.send(1, bytes(new_packet))

    def send_icmp_time_exceeded(self, pkt):
        """
        Create ICMP time exceeded packet, which will be sent to source after ttl is 0
        :param pkt: Packet whoe ttl is 0
        """
        # Create ICMP time exceeded packet
        new_packet = Ether() / RouterCPUMetadata() / IP() / ICMP() / pkt[IP]

        new_packet[RouterCPUMetadata].fromCpu = 1
        new_packet[RouterCPUMetadata].srcPort = 1
        new_packet[RouterCPUMetadata].origEthType = 0x800

        new_packet[IP].dst = pkt[IP].src
        new_packet[IP].src = self.intfs[pkt[RouterCPUMetadata].srcPort - 2].ip_addr
        new_packet[IP].ihl = 5
        new_packet[IP].proto = 0x1
        new_packet[IP].len = len(new_packet[IP])

        new_packet[ICMP].type = 11
        new_packet[ICMP].code = 0

        # Send packet to data plane
        self.send(1, bytes(new_packet))

    def handle_icmp_request(self, pkt):
        """
        Create reply to ICMP echo request
        :param pkt: ICMP echo request packet that we answer to
        """
        # TODO: Fix time of reply stored in data section of packet

        # Create ICMP echo reply
        new_packet = Ether() / RouterCPUMetadata() / IP() / ICMP()

        new_packet[Ether].dst = pkt[Ether].src
        new_packet[Ether].src = pkt[Ether].dst

        new_packet[RouterCPUMetadata].fromCpu = 1
        new_packet[RouterCPUMetadata].origEthType = 0x800
        new_packet[RouterCPUMetadata].srcPort = pkt[RouterCPUMetadata].dstPort
        new_packet[RouterCPUMetadata].dstPort = pkt[RouterCPUMetadata].srcPort

        new_packet[IP].src = pkt[IP].dst
        new_packet[IP].dst = pkt[IP].src
        new_packet[IP].ttl = 64

        new_packet[ICMP].type = 0
        new_packet[ICMP].code = 0
        new_packet[ICMP].seq = pkt[ICMP].seq
        new_packet[ICMP].id = pkt[ICMP].id

        # Send packet to data plane
        self.send(1, bytes(new_packet))

    def handle_pwospf(self, pkt):
        pass

    def handle_packet(self, packet: bytes):
        """
        Process packet received from sniffer
        :param packet: Packet received from sniffer
        """
        # Parse packet to Scapy headers
        pkt = Ether(packet)
        # Check whether packet has RouterCPUMetadata header
        if RouterCPUMetadata not in pkt:
            print("Error: Packets coming to CPU should have special header router")
            return

        pkt[RouterCPUMetadata].fromCpu = 1

        # Main logic of packet handler
        if pkt[RouterCPUMetadata].opType == 1:
            self.send_arp_request(pkt)
        elif pkt[RouterCPUMetadata].opType == 2:
            self.handle_arp_reply(pkt)
        elif pkt[RouterCPUMetadata].opType == 3:
            self.send_icmp_time_exceeded(pkt)
        elif pkt[RouterCPUMetadata].opType == 4:
            self.handle_icmp_request(pkt)
        elif pkt[RouterCPUMetadata].opType == 5:
            self.handle_pwospf(pkt)

    def run(self):
        """
        Main loop of the switch controller
        """
        sniff(self.intf, self.handle_packet, self.stop_event)

    def start(self):
        """
        Start the switch controller
        """
        super(RouterController, self).start()

    def join(self, timeout=None):
        """
        Join the switch controller
        :param timeout: Time after joining is timed out
        """
        self.stop()
        super(RouterController, self).join()

    def stop(self):
        """
        Stop the switch controller
        """
        self.stop_event.set()
        print("Stopping controller....")
