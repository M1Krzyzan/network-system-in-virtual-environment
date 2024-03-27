import socket
from time import time, sleep
from sniffer import sniff
from threading import Thread, Event
from p4runtime_lib.convert import *
from headers.router_cpu_metadata import RouterCPUMetadata
from headers.pwospf import PWOSPF, Hello, LSU, LSUad
from scapy.all import Ether, ARP, IP, ICMP


class Interface:
    def __init__(self, mac_addr, ip_addr, mask, port, hello_int):
        """
        Initialize an Interface object.
        
        Parameters:
            mac_addr (str): MAC address of the interface.
            ip_addr (str): IP address of the interface.
            mask (str): Subnet mask of the interface.
            port (int): Port number of the interface.
            hello_int (int): Hello interval for OSPF protocol.
        """
        self.ip_addr = ip_addr
        self.mask = mask
        self.hello_int = hello_int
        self.mac_addr = mac_addr
        self.port = port
        self.neighbours = []  # List to store neighboring routers
        self.neighbours_times = {}  # Dictionary to store timestamps of neighbor updates

    def add_neighbor(self, router_id, interface_ip):
        """
        Add a neighbor to the interface's neighbor list.

        Parameters:
            router_id (str): ID of the neighboring router.
            interface_ip (str): IP address of the neighboring interface.
        """
        self.neighbours.append((router_id, interface_ip))  # Add neighbor to list

    def remove_neighbor(self, router_id, interface_ip):
        """
        Remove a neighbor from the interface's neighbor list.

        Parameters:
            router_id (str): ID of the neighboring router.
            interface_ip (str): IP address of the neighboring interface.
        """
        self.neighbours.remove((router_id, interface_ip))  # Remove neighbor from list
        self.neighbours_times.pop((router_id, interface_ip))  # Remove neighbor timestamp

    def update_time(self, router_id, intf_ip):
        """
        Update the timestamp for a neighbor on the interface.

        Parameters:
            router_id (str): ID of the neighboring router.
            intf_ip (str): IP address of the neighboring interface.
        """
        self.neighbours_times[(router_id, intf_ip)] = time()  # Update neighbor timestamp

class RouterController(Thread):
    def __init__(self, router, router_intfs, area_id=1, lsu_int=30):
        """
        Initialize a RouterController object.

        Parameters:
            router: Router object.
            router_intfs (list): List of tuples containing interface information.
            area_id (int): OSPF area ID.
            lsu_int (int): LSU interval.
        """
        super(RouterController, self).__init__()
        self.router = router
        self.intf = router.intfs[1].name
        self.stop_event = Event()
        self.stored_packet = None
        self.intfs = []  # List to store router interfaces
        self.arp_table = {}  # ARP table
        self.hello_mngrs = []  # List to store HelloManager instances

        # Initialize interfaces
        for intf in router_intfs:
            self.intfs.append(Interface(intf[0], intf[1], intf[2], intf[3], 3))

        # PWOSPF fields
        self.router_id = self.intfs[0].ip_addr
        self.area_id = area_id
        self.lsu_int = lsu_int

        # Initialize HelloManager for each interface
        for i in self.intfs:
            self.hello_mngrs.append(HelloManager(self, i))
            
    def send(self, port: int, pkt: bytes):
        """
        Send packet to correct interface which is identified by port of switch
        
        Parameters:
            port (int): Port number which corresponds to the interface of switch
            pkt (bytes): Packet to send
        """
        raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((self.router.intfs[port].name, 0))
        raw_socket.send(pkt)
        raw_socket.close()

    def print_neigh(self):
        """
        Print neighbors of each interface.
        """
        for intf in self.intfs:
            print("Intf:", intf.ip_addr, "neigh:", intf.neighbours)

    def handle_arp_reply(self, pkt):
        """
        Process arp reply by adding entry of requested pair - mac address and ip address
        to data plane arp table and copy contained by controller
        
        Parameters:
            pkt: Packet to process
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
            
    def send_arp_request(self, pkt):
        """
        Create arp request packet, which will be sent to port with unknown mac address
        
        Parameters:
            pkt: Packet stored to be sent after reply will arrive
        """
        # Store packet in controller
        self.stored_packet = pkt
        # Create arp request packet
        new_packet = Ether() / RouterCPUMetadata() / ARP()

         # Setting up ARP request packet fields
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
        
        Parameters:
            pkt: Packet whose ttl is 0
        """
        # Create ICMP time exceeded packet
        new_packet = Ether() / RouterCPUMetadata() / IP() / ICMP() / pkt[IP]
        
        # Setting up ICMP time exceeded packet fields
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
        
        Parameters:
            pkt: ICMP echo request packet that we answer to
        """
        # Create ICMP echo reply packet
        new_packet = Ether() / RouterCPUMetadata() / IP() / ICMP() / pkt[ICMP].payload

        # Setting up ICMP echo reply packet fields
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

    def handle_hello(self, pkt):
        """
        Handle incoming Hello packets.
        
        Parameters:
            pkt: Hello packet received
        """
        if pkt[PWOSPF].version != 2 or pkt[PWOSPF].areaID != self.area_id:
            return
        if pkt[PWOSPF].auType != 0 or pkt[PWOSPF].auth != 0:
            return

        intf = self.intfs[pkt[RouterCPUMetadata].srcPort - 2]

        if pkt[Hello].netmask != intf.mask:
            return
        if pkt[Hello].helloint != intf.hello_int:
            return

        router_id = pkt[PWOSPF].routerID
        intf_ip = pkt[IP].src

        if (router_id, intf_ip) in intf.neighbours:
            intf.update_time(router_id, intf_ip)
        else:
            intf.add_neighbor(router_id, intf_ip)

    def handle_lsu(self, pkt):
        pass

    # Method to handle incoming packets
    def handle_packet(self, packet: bytes):
        """
        Process packet received from sniffer
        
        Parameters:
            packet: Packet received from sniffer
        """
        # Parse packet to Scapy headers
        pkt = Ether(packet)

        # Check whether packet has RouterCPUMetadata header
        if RouterCPUMetadata not in pkt:
            pkt.show()
            print("Error: Packets coming to CPU should have special header router")
            return
        if pkt[RouterCPUMetadata].fromCpu == 1:
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
            self.handle_hello(pkt)
        elif pkt[RouterCPUMetadata].opType == 6:
            self.handle_lsu(pkt)
        else:
            pkt.show()
            print("This packet shouldn't be sent to CPU")

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
        for mngr in self.hello_mngrs:
            mngr.start()

    def stop(self):
        """
        Stop the switch controller
        """
        self.stop_event.set()
        print("Stopping controller....")

class HelloManager(Thread):
    def __init__(self, cntrl: RouterController, intf: Interface):
        """
        Initialize a HelloManager object.

        Parameters:
            cntrl (RouterController): RouterController instance managing the router.
            intf (Interface): Interface associated with this HelloManager.
        """
        super(HelloManager, self).__init__()
        self.cntrl = cntrl  # RouterController instance managing the router
        self.intf = intf  # Interface associated with this HelloManager

    def check_times(self):
        """
        Check the timestamps of neighbor updates and remove neighbors that have not sent updates.
        """
        now = time()
        for n in self.intf.neighbours:
            then = self.intf.neighbours_times.setdefault((n[0], n[1]), now)
            if (now - then) > 3 * self.intf.hello_int:
                print(now-then)
                self.intf.remove_neighbor(n[0], n[1])

    def send_hello(self):
        """
        Send Hello packets periodically to maintain neighbor relationships.
        """
        # Construct Hello packet
        packet = Ether() / RouterCPUMetadata() / IP() / PWOSPF() / Hello()
        
        # Setting up Hello packet fields
        packet[Ether].src = self.intf.mac_addr
        packet[Ether].dst = "ff:ff:ff:ff:ff:ff"
        packet[Ether].type = 0x80b

        packet[RouterCPUMetadata].fromCpu = 1
        packet[RouterCPUMetadata].origEthType = 0x800
        packet[RouterCPUMetadata].dstPort = self.intf.port

        packet[IP].src = self.intf.ip_addr
        packet[IP].dst = "224.0.0.5"
        packet[IP].proto = 0x59

        packet[PWOSPF].version = 2
        packet[PWOSPF].type = 0x1
        packet[PWOSPF].length = 0
        packet[PWOSPF].routerID = self.cntrl.router_id
        packet[PWOSPF].areaID = self.cntrl.area_id
        packet[PWOSPF].checksum = 0

        packet[Hello].netmask = self.intf.mask
        packet[Hello].helloint = self.intf.hello_int
        
        # Send Hello packet
        self.cntrl.send(1, bytes(packet))

    def run(self):
        """
        Run method for HelloManager thread.
        """
        while not self.cntrl.stop_event.is_set():
            self.send_hello()  # Send Hello packets
            self.check_times()  # Check neighbor timestamps
            sleep(self.intf.hello_int)  # Wait for Hello interval
