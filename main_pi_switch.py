import argparse
import os

from p4runtime_lib import bmv2
from p4runtime_lib import helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from controller_switch import SwitchController

def main():
    parser = argparse.ArgumentParser(description="P4Runtime Controller")

    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("File %s does not exist!" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("File %s does not exist!" % args.bmv2_json)
        parser.exit(1)
    # main(args.p4info, args.bmv2_json)
    p4info_helper = helper.P4InfoHelper(args.p4info)
    s1 = bmv2.Bmv2SwitchConnection(name='s1', proto_dump_file="logs/s1-p4runtime-requests.txt")
    s1.MasterArbitrationUpdate()
    s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=args.bmv2_json)

    s1.addMulticastGroup(p4info_helper, mgid=1, ports=range(2, 5))
    s1.insertTableEntry(p4info_helper, table_name='ingress_control.l2_forwarding',
                        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
                        action_name='ingress_control.multicast',
                        action_params={'mgid': 1})

    cpu = SwitchController(s1, p4info_helper)
    cpu.start()
   
if __name__ == "__main__":
    main()
