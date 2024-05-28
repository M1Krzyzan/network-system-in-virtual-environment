from scapy.fields import BitField, ByteField, XShortField, IPField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x080b


class RouterCPUMetadata(Packet):
    name = "RouterCPUMetadata"
    fields_desc = [BitField("fromCpu", 0,1),
                   BitField("opType", 0, 5),
                   BitField("srcPort", None,9),
                   BitField("dstPort",None, 9),
                   XShortField("origEthType", None),
                   IPField("nextHop", None)]


bind_layers(Ether, RouterCPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(RouterCPUMetadata, IP, origEthType=0x0800)
bind_layers(RouterCPUMetadata, ARP, origEthType=0x0806)
