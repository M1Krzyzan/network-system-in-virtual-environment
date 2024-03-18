from scapy.fields import BitField, ByteField, XShortField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x080a


class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [BitField("fromCpu", 0,7),
                   BitField("srcPort", None,9),
                   XShortField("origEthType", None)]


bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEthType=0x0800)
bind_layers(CPUMetadata, ARP, origEthType=0x0806)
