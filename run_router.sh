set -e

if ![test -f ./router.p4]; then{
  echo "File router.p4 not found in running directory"
  exit 1
}
fi

if ![test -f /root/bmv2/bin/router.json] || ![test -f /root/bmv2/bin/router.p4info.txt]; then
  sudo p4c-bm2-ss -I /usr/share/p4c/p4include --std p4-16 --p4runtime-files /root/bmv2/bin/router.p4info.txt -o /root/bmv2/bin/router.json router.p4
fi

if ![test -f ./$1]; then{
  echo "File $1 not found in running directory"
  exit 1
}
fi
config=cat $1

run_simple_switch_grpc = "sudo simple_switch_grpc -i 1@eth0"

i=2
# Read JSON data and process each entry
echo "$json_data" | jq -c '.[]' | while read -r entry; do
    # Extract IP, MASK, and MAC
    ip=$(echo "$entry" | jq -r '.IP')
    mask=$(echo "$entry" | jq -r '.MASK')
    mac=$(echo "$entry" | jq -r '.MAC')

    # Create interface name based on MAC address
    iface_name="enx${mac//:/}"

    # Add interface to simple_switch_grpc command parameters
    run_simple_switch_grpc = "${run_simple_switch_grpc} -i ${i}@${iface_name}"
    i=i+1

    # Assign IP address to the interface
    sudo ifconfig iface_name ${ip} netmask ${mask}

done

sudo ip link add eth0 type dummy

run_simple_switch_grpc = "${run_simple_switch_grpc} /root/bmv2/bin/router.json -- --grpc-server-addr 127.0.0.1:50051 &"
$run_simple_switch_grpc

if ![test -f ./main_pi_router.py]; then{
  echo "File main_pi_router.py not found in running directory"
  exit 1
}
fi

sudo python3 main_pi_router.py --p4info /root/bmv2/bin/router.p4info.txt --bmv2-json /root/bmv2/bin/router.json --intfs-config $1 &
