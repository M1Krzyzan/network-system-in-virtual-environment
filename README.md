# Network System Design and Implementation in Virtual Environment

## Description
This project focuses on designing and implementing a network system in a virtual environment. Components of the system such as routers and switches should fulfill their basic functionalities. Additionally, the router should be capable of detecting failures and effectively bypassing them.

## Tools
- **P4APP**: Running, building, debugging, and testing programs in P4 language.
- **Mininet**: Network virtualization software.
- **p4c**: P4 program compiler.
- **P4Pi**: Open-source platform enabling the execution of P4 programs on Raspberry Pi.

## Technologies
- **Python**: Programming language.
- **P4**: Programming language for data plane in networks.
- **BMV2**: Software-based switch where P4 compiled programs run.
- **Socket**: Library for creating sockets to send or receive incoming packets.
- **Scapy**: Python library for packet creation, manipulation, and sending/receiving.
- **P4Runtime**: Interface for local network control layer managing data plane in P4, monitoring packet forwarding rules, and device status.

## PW-OSPF
 PWOSPF is a greatly simplified link state routing protocol based on OSPFv2
  (rfc 1247).  Like OSPFv2, routers participating in a PWOSPF topology
  periodically broadcast HELLO packets to discover and maintain a list of
  neighbors.  Whenever a change in a link status is detected (for example the
  addition or deletion of a router to the topology) or a timeout occurs, each
  router floods its view of the network throughout the topology so that each
  router has a complete database of the network connectivity.  Djikstra's
  algorithm is used by each router independently to determine the next
  hop in the forwarding table to all advertised routes.
## Topology
![Topology of the network designed in Mininet environment.](https://github.com/Wflikeit/NetworkSystemsInVirtualEnvironment/blob/main/img/Topology.jpg?raw=true)

## Implementation requirements
### Router

#### Data Plane

- Packet processor responsible for processing incoming packets to the router
- Routing table, which matches the longest prefix on the destination address to connect the IP address of the next device with the output port
- ARP table, which establishes the destination MAC address based on the next hop IP
- TTL value checking and decrementation
- Updating the source MAC address based on the set output port
- Sending the packet through the pre-established output port
- Forwarding packets destined for the local router to the local control plane
- Rejecting packets of protocols other than those specified during parsing to the local control plane
- Rejecting incorrect IP packets

#### Control Plane

- ARP table update
- Sending ARP queries
- Generating ICMP packets about host unavailability
- Responding to ICMP echo requests
- Creating forwarding table through PW-OSPF dynamic routing protocol
- Supporting static routing table in addition to PW-OSPF protocol paths
- Handling packets directed directly to the router
- Sending and receiving PW-OSPF protocol packets

### Switch

#### Data Plane

- Packet processor responsible for processing incoming packets to the switch
- MAC address table performing an exact match of the destination MAC address of the device and sending the packet to the appropriate output port or multicast group
- Sending a notification to the control plane about a new binding of the source MAC address to the port

#### Control Plane

- Updating the table containing MAC address and output port pairs
- Multicast group configuration

