from p4app import P4Mininet, P4Program
from mininet.topo import Topo
from mininet.cli import CLI
from controller_switch import SwitchController
from controller_router import RouterController
from time import sleep

router_prog = P4Program('router.p4')
switch_prog = P4Program('switch.p4')


class MyTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        cpu = self.addHost('cpu')
        cpu1 = self.addHost('cpu1')
        cpu2 = self.addHost('cpu2')
        cpu3 = self.addHost('cpu3')

        h1 = self.addHost('h1',
                          ip='20.0.0.2/24',
                          mac='00:00:14:00:00:02',
                          defaultRoute='via 20.0.0.1')

        h2 = self.addHost('h2',
                          ip='102.168.0.2/24',
                          mac='00:00:66:a8:00:02',
                          defaultRoute='via 102.168.0.1')
        h3 = self.addHost('h3',
                          ip='102.168.0.3/24',
                          mac='00:00:66:a8:00:03',
                          defaultRoute='via 102.168.0.1')

        r1 = self.addSwitch('r1', program=router_prog)
        r2 = self.addSwitch('r2', program=router_prog)
        r3 = self.addSwitch('r3', program=router_prog)

        s1 = self.addSwitch('s1', program=switch_prog)

        self.addLink(s1, cpu, port1=1)
        self.addLink(r1, cpu1, port1=1)
        self.addLink(r2, cpu2, port1=1)
        self.addLink(r3, cpu3, port1=1)

        self.addLink(h2, s1, port2=2)
        self.addLink(h3, s1, port2=3)

        self.addLink(r2, h1, port1=2)

        self.addLink(r1, s1, port1=2, port2=4)
        self.addLink(r1, r2, port1=3, port2=3)
        self.addLink(r1, r3, port1=4, port2=2)

        self.addLink(r2, r3, port1=4, port=3)


def main():
    topo = MyTopo()
    net = P4Mininet(program='switch.p4', topo=topo, auto_arp=False)
    net.start()

    sw = net.get('s1')
    r1 = net.get('r1')
    r2 = net.get('r2')
    r3 = net.get('r3')

    # r1.setMAC('00:00:66:a8:00:01', 'r1-eth2')
    # r1.setMAC('00:00:c0:a8:01:01', 'r1-eth3')
    # r1.setMAC('00:00:c0:a8:02:02', 'r1-eth4')
    #
    # r2.setMAC('00:00:14:00:00:01', 'r2-eth2')
    # r2.setMAC('00:00:c0:a8:01:02', 'r2-eth3')
    # r2.setMAC('00:00:c0:a8:03:01', 'r2-eth4')
    #
    # r3.setMAC('00:00:c0:a8:02:01', 'r3-eth2')
    # r3.setMAC('00:00:c0:a8:03:02', 'r3-eth3')

    sw.addMulticastGroup(mgid=1, ports=range(2, 5))

    # sw.insertTableEntry(table_name='ingress_control.l2_forwarding',
    #                    match_fields={'hdr.ethernet.dstAddr': ["00:00:66:a8:00:02"]},
    #                    action_name='ingress_control.forward',
    #                    action_params={'egress_port': 2})
    # sw.insertTableEntry(table_name='ingress_control.l2_forwarding',
    #                    match_fields={'hdr.ethernet.dstAddr': ["00:00:66:a8:00:03"]},
    #                    action_name='ingress_control.forward',
    #                    action_params={'egress_port': 3})
    # sw.insertTableEntry(table_name='ingress_control.l2_forwarding',
    #                    match_fields={'hdr.ethernet.dstAddr': ["00:00:66:a8:00:01"]},
    #                    action_name='ingress_control.forward',
    #                    action_params={'egress_port': 4})
    sw.insertTableEntry(table_name='ingress_control.l2_forwarding',
                        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
                        action_name='ingress_control.multicast',
                        action_params={'mgid': 1})

    # sw.insertTableEntry(table_name='ingress_control.learned_src',
    #                    match_fields={'hdr.ethernet.srcAddr': ["00:00:66:a8:00:02"]},
    #                    action_name='NoAction')
    # sw.insertTableEntry(table_name='ingress_control.learned_src',
    #                    match_fields={'hdr.ethernet.srcAddr': ["00:00:66:a8:00:03"]},
    #                    action_name='NoAction')
    # sw.insertTableEntry(table_name='ingress_control.learned_src',
    #                    match_fields={'hdr.ethernet.srcAddr': ["00:00:66:a8:00:01"]},
    #                    action_name='NoAction')

    # MULTICAST GROUPS FOR ROUTER
    r1.addMulticastGroup(mgid=1, ports=range(2, 5))
    r2.addMulticastGroup(mgid=1, ports=range(2, 5))
    r3.addMulticastGroup(mgid=1, ports=range(2, 4))

    r1.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "255.255.255.255"},
                        action_name='ingress_control.multicast',
                        action_params={'mgid': 1})
    r2.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "255.255.255.255"},
                        action_name='ingress_control.multicast',
                        action_params={'mgid': 1})
    r3.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "255.255.255.255"},
                        action_name='ingress_control.multicast',
                        action_params={'mgid': 1})

    # LOCAL IP TABLE
    r1.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "224.0.0.5"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})
    r1.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "102.168.0.1"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})
    r1.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "192.168.1.1"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})
    r1.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "192.168.2.2"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})

    # r1.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "102.168.0.2"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 2})
    # r1.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "102.168.0.3"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 2})
    # r1.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "192.168.1.2"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 3})
    # r1.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "192.168.2.1"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 4})

    r2.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "224.0.0.5"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})
    r2.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "20.0.0.1"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})
    r2.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "192.168.1.2"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})
    r2.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "192.168.3.1"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})

    # r2.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "20.0.0.2"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 2})
    # r2.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "192.168.1.1"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 3})
    # r2.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "192.168.3.2"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 4})

    r3.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "224.0.0.5"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})
    r3.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "192.168.2.1"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})
    r3.insertTableEntry(table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "192.168.3.2"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})

    # r3.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "192.168.2.2"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 2})
    # r3.insertTableEntry(table_name='ingress_control.local_ip_table',
    #                     match_fields={'hdr.ipv4.dstAddr': "192.168.3.1"},
    #                     action_name='ingress_control.set_sintf',
    #                     action_params={'egress_port': 3})
    # ARP TABLE
    # r1.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "192.168.1.2"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': "00:00:c0:a8:01:02"})
    # r1.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "192.168.2.1"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': '00:00:c0:a8:02:01'})
    # r1.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "102.168.0.2"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': '00:00:66:a8:00:02'})
    # r1.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "102.168.0.3"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': '00:00:66:a8:00:03'})

    # r2.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "192.168.1.1"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': '00:00:c0:a8:01:01'})
    # r2.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "20.0.0.2"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': '00:00:14:00:00:02'})
    # r2.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "192.168.3.1"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': '00:00:c0:a8:03:01'})

    # r3.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "192.168.3.2"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': "00:00:c0:a8:03:02"})
    # r3.insertTableEntry(table_name='ingress_control.arp_table',
    #                    match_fields={'next_hop': "192.168.0.3"},
    #                    action_name='ingress_control.set_dmac',
    #                    action_params={'mac_dest': "00:00:66:a8:00:03"})

    # routing table
    # r1.insertTableEntry(table_name='ingress_control.ipv4_lpm',
    #                     default_action=True,
    #                     action_name='ingress_control.set_nhop',
    #                     action_params={'nhop': '192.168.2.1', 'egress_port': 3})
    # r1.insertTableEntry(table_name='ingress_control.ipv4_lpm',
    #                     match_fields={'hdr.ipv4.dstAddr': ["20.0.0.0", 24]},
    #                     action_name='ingress_control.set_nhop',
    #                     action_params={'nhop': '192.168.1.2', 'egress_port': 3})
    #
    # r2.insertTableEntry(table_name='ingress_control.ipv4_lpm',
    #                     default_action=True,
    #                     action_name='ingress_control.set_nhop',
    #                     action_params={'nhop': '192.168.3.2', 'egress_port': 3})
    # r2.insertTableEntry(table_name='ingress_control.ipv4_lpm',
    #                     match_fields={'hdr.ipv4.dstAddr': ["102.168.0.0", 24]},
    #                     action_name='ingress_control.set_nhop',
    #                     action_params={'nhop': '192.168.1.1', 'egress_port': 3})
    # r2.insertTableEntry(table_name='ingress_control.ipv4_lpm',
    #                     match_fields={'hdr.ipv4.dstAddr': ["192.168.2.0", 24]},
    #                     action_name='ingress_control.set_nhop',
    #                     action_params={'nhop': '192.168.3.1', 'egress_port': 4})
    #
    # r3.insertTableEntry(table_name='ingress_control.ipv4_lpm',
    #                     match_fields={'hdr.ipv4.dstAddr': ["102.168.0.0", 24]},
    #                     action_name='ingress_control.set_nhop',
    #                     action_params={'nhop': '192.168.2.2', 'egress_port': 2})
    # r3.insertTableEntry(table_name='ingress_control.ipv4_lpm',
    #                     match_fields={'hdr.ipv4.dstAddr': ["20.0.0.0", 24]},
    #                     action_name='ingress_control.set_nhop',
    #                     action_params={'nhop': '192.168.3.1', 'egress_port': 3})

    # src mac rewrite
    r1.insertTableEntry(table_name='egress_control.mac_rewriting_table',
                        match_fields={'standard_metadata.egress_port': 2},
                        action_name='egress_control.set_smac',
                        action_params={'smac': '00:00:66:a8:00:01'})
    r1.insertTableEntry(table_name='egress_control.mac_rewriting_table',
                        match_fields={'standard_metadata.egress_port': 3},
                        action_name='egress_control.set_smac',
                        action_params={'smac': '00:00:c0:a8:01:01'})
    r1.insertTableEntry(table_name='egress_control.mac_rewriting_table',
                        match_fields={'standard_metadata.egress_port': 4},
                        action_name='egress_control.set_smac',
                        action_params={'smac': '00:00:c0:a8:02:02'})

    r2.insertTableEntry(table_name='egress_control.mac_rewriting_table',
                        match_fields={'standard_metadata.egress_port': 2},
                        action_name='egress_control.set_smac',
                        action_params={'smac': '00:00:14:00:00:01'})
    r2.insertTableEntry(table_name='egress_control.mac_rewriting_table',
                        match_fields={'standard_metadata.egress_port': 3},
                        action_name='egress_control.set_smac',
                        action_params={'smac': '00:00:c0:a8:01:02'})
    r2.insertTableEntry(table_name='egress_control.mac_rewriting_table',
                        match_fields={'standard_metadata.egress_port': 4},
                        action_name='egress_control.set_smac',
                        action_params={'smac': '00:00:c0:a8:03:01'})

    r3.insertTableEntry(table_name='egress_control.mac_rewriting_table',
                        match_fields={'standard_metadata.egress_port': 2},
                        action_name='egress_control.set_smac',
                        action_params={'smac': '00:00:c0:a8:02:01'})
    r3.insertTableEntry(table_name='egress_control.mac_rewriting_table',
                        match_fields={'standard_metadata.egress_port': 3},
                        action_name='egress_control.set_smac',
                        action_params={'smac': '00:00:c0:a8:03:02'})

    # arp reply table
    r1.insertTableEntry(table_name='ingress_control.arp_reply_table',
                        match_fields={'hdr.arp.dstIP': "102.168.0.1"},
                        action_name='ingress_control.reply',
                        action_params={'intfAddr': '00:00:66:a8:00:01'})
    r1.insertTableEntry(table_name='ingress_control.arp_reply_table',
                        match_fields={'hdr.arp.dstIP': "192.168.1.1"},
                        action_name='ingress_control.reply',
                        action_params={'intfAddr': '00:00:c0:a8:01:01'})
    r1.insertTableEntry(table_name='ingress_control.arp_reply_table',
                        match_fields={'hdr.arp.dstIP': "192.168.2.2"},
                        action_name='ingress_control.reply',
                        action_params={'intfAddr': '00:00:c0:a8:02:02'})

    r2.insertTableEntry(table_name='ingress_control.arp_reply_table',
                        match_fields={'hdr.arp.dstIP': "20.0.0.1"},
                        action_name='ingress_control.reply',
                        action_params={'intfAddr': '00:00:14:00:00:01'})
    r2.insertTableEntry(table_name='ingress_control.arp_reply_table',
                        match_fields={'hdr.arp.dstIP': "192.168.1.2"},
                        action_name='ingress_control.reply',
                        action_params={'intfAddr': '00:00:c0:a8:01:02'})
    r2.insertTableEntry(table_name='ingress_control.arp_reply_table',
                        match_fields={'hdr.arp.dstIP': "192.168.3.1"},
                        action_name='ingress_control.reply',
                        action_params={'intfAddr': '00:00:c0:a8:03:01'})

    r3.insertTableEntry(table_name='ingress_control.arp_reply_table',
                        match_fields={'hdr.arp.dstIP': "192.168.2.1"},
                        action_name='ingress_control.reply',
                        action_params={'intfAddr': '00:00:c0:a8:02:01'})
    r3.insertTableEntry(table_name='ingress_control.arp_reply_table',
                        match_fields={'hdr.arp.dstIP': "192.168.3.2"},
                        action_name='ingress_control.reply',
                        action_params={'intfAddr': '00:00:c0:a8:03:02'})

    net.get('h3').cmd('ip r add default via 102.168.0.1')

    net.get('h2').cmd('ip r add default via 102.168.0.1')

    net.get('h1').cmd('ip r add default via 20.0.0.1')

    r1_intfs = [('00:00:66:a8:00:01', '102.168.0.1', '255.255.255.0', 2),
                ('00:00:c0:a8:00:01', '192.168.1.1', '255.255.255.0', 3),
                ('00:00:c0:a8:00:02', '192.168.2.2', '255.255.255.0', 4)]

    r2_intfs = [('00:00:14:00:00:01', '20.0.0.1', '255.255.255.0', 2),
                ('00:00:c0:a8:01:02', '192.168.1.2', '255.255.255.0', 3),
                ('00:00:c0:a8:03:01', '192.168.3.1', '255.255.255.0', 4)]

    r3_intfs = [('00:00:c0:a8:02:01', '192.168.2.1', '255.255.255.0', 2),
                ('00:00:c0:a8:03:02', '192.168.3.2', '255.255.255.0', 3)]

    cpu = SwitchController(sw)
    cpu.start()

    cpu1 = RouterController(r1, r1_intfs)
    cpu2 = RouterController(r2, r2_intfs)
    cpu3 = RouterController(r3, r3_intfs)

    cpu1.start()
    cpu2.start()
    cpu3.start()
    try:
        CLI(net)
    finally:
        cpu.stop()
        cpu1.stop()
        cpu2.stop()
        cpu3.stop()
        net.stop()


if __name__ == '__main__':
    main()
