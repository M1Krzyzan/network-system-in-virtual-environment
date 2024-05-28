import socket


def sniff(intf, handle_packet, stop_event):
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    raw_socket.bind((intf, 0))
    while not stop_event.is_set():
        try:
            pkt = raw_socket.recvfrom(65565)
            if pkt:
                handle_packet(pkt[0])
        except OSError:
            raw_socket.close()
            print("Stopped")
            break
        except Exception as e:
            print("Exception occured:", e)
            continue
    
