import argparse
import os
import json
from p4runtime_lib import bmv2
from p4runtime_lib import helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from controller_router import RouterController


def main():
    parser = argparse.ArgumentParser(description="P4Runtime Controller")

    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    parser.add_argument('--intfs-config', help='Intfs config JSON file',
                        type=str, action="store", required=True)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("File %s does not exist!" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("File %s does not exist!" % args.bmv2_json)
        parser.exit(1)

    try:
        with open(args.intfs_config, 'r') as file:
            intfs = json.load(file)
        print("Intfs config JSON data loaded successfully!")
        print(type(intfs))
    except FileNotFoundError:
        print(f"File {args.intfs_config} does not exist!")
        parser.exit(1)
    except json.JSONDecodeError:
        print("Failed to decode JSON from the intfs-config file. Please check the file format.")
        parser.exit(1)

    p4info_helper = helper.P4InfoHelper(args.p4info)
    if not os.path.isdir("logs"):
        os.mkdir("logs")
    r1 = bmv2.Bmv2SwitchConnection(name='r1', proto_dump_file="logs/r1-p4runtime-requests.txt")
    r1.MasterArbitrationUpdate()
    r1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=args.bmv2_json)

    r1.addMulticastGroup(p4info_helper, mgid=1, ports=range(2, 5))
    r1.insertTableEntry(p4info_helper, table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "255.255.255.255"},
                        action_name='ingress_control.multicast',
                        action_params={'mgid': 1})
    r1.insertTableEntry(p4info_helper, table_name='ingress_control.local_ip_table',
                        match_fields={'hdr.ipv4.dstAddr': "224.0.0.5"},
                        action_name='ingress_control.set_sintf',
                        action_params={'egress_port': 1})

    for i in range(0,len(intfs)):
        r1.insertTableEntry(p4info_helper, table_name='ingress_control.local_ip_table',
                            match_fields={'hdr.ipv4.dstAddr': intfs[i]["IP"]},
                            action_name='ingress_control.set_sintf',
                            action_params={'egress_port': 1})
        r1.insertTableEntry(p4info_helper, table_name='egress_control.mac_rewriting_table',
                            match_fields={'standard_metadata.egress_port': i+2},
                            action_name='egress_control.set_smac',
                            action_params={'smac': '00:00:66:a8:00:01'})
        r1.insertTableEntry(p4info_helper, table_name='ingress_control.arp_reply_table',
                            match_fields={'hdr.arp.dstIP': intfs[i]["IP"]},
                            action_name='ingress_control.reply',
                            action_params={'intfAddr': intfs[i]["MAC"]})

    cpu = RouterController(r1, p4info_helper, intfs)
    cpu.start()


if __name__ == "__main__":
    main()
