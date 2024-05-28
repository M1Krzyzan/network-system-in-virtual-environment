import socket
from sniffer import sniff
from threading import Thread, Event
from p4runtime_lib.convert import *
from headers.switch_cpu_metadata import CPUMetadata
from scapy.all import Ether


class SwitchController(Thread):
    def __init__(self, switch, p4info_helper):
        """
        Initialize a SwitchController object.

        Parameters:
            switch: Switch object to be controlled.
        """
        super(SwitchController, self).__init__()
        self.switch = switch  # Switch object
        self.p4info = p4info_helper
        self.stop_event = Event()  # Event to signal stopping the controller
        self.forwarding_table = {}  # Forwarding table to store routing information

    def add_forwarding_table_entry(self, port: int, mac_addr: str):
        """
        Add entry into the L2 forwarding table and entry into the learned MAC addresses table
        :param port: Port number on which the switch received the packet
        :param mac_addr: MAC address of the interface from which the switch received the packet
        """
        if mac_addr in self.forwarding_table:
            return
        self.forwarding_table[mac_addr] = port

        self.switch.insertTableEntry(self.p4info, table_name='ingress_control.l2_forwarding',
                                     match_fields={'hdr.ethernet.dstAddr': [mac_addr]},
                                     action_name='ingress_control.forward',
                                     action_params={'egress_port': port})
        self.switch.insertTableEntry(self.p4info,table_name='ingress_control.learned_src',
                                     match_fields={'hdr.ethernet.srcAddr': [mac_addr]},
                                     action_name='NoAction')

    def send(self, port: int, pkt: bytes):
        """
        Send packet to correct interface which is identified by port of switch
        :param port: Port number which corresponds to the interface of switch
        :param pkt: Packet to send
        """
        raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind(('eth0', 0))
        raw_socket.send(pkt)

    def handle_packet(self, packet: bytes):
        """
        Process received packet from sniffer
        :param packet: Packet received from sniffer
        """
        pkt = Ether(packet)
        pkt.show()
        if CPUMetadata not in pkt:
            print("Error: Packets coming to CPU should have special header/ switch")
            return
        if pkt[CPUMetadata].fromCpu == 1:
            return

        pkt[CPUMetadata].fromCpu = 1
        self.add_forwarding_table_entry(pkt[CPUMetadata].srcPort, pkt[Ether].src)
        self.send(pkt[CPUMetadata].srcPort, bytes(pkt))

    def run(self):
        """
        Main loop of the switch controller
        """
        sniff('eth0', self.handle_packet, self.stop_event)

    def start(self):
        """
        Start the switch controller
        """
        super(SwitchController, self).start()

    def stop(self):
        """
        Stop the switch controller
        """
        self.stop_event.set()
        print("Stopping controller....")
