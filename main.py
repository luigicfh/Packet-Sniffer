import os
import sys
from scapy.all import *

target_ip = "192.168.0.4"
conf.use_pcap = True


def packet_handler(packet):
    """
    This function will be called for each captured packet.
    You can process the packet or print its details here.
    """
    print(packet.summary())
    # if packet.haslayer("TCP") and packet.haslayer("Raw") and "IP" in packet:
    #     # Check if the packet contains an HTTP request (method + URI)
    #     print("Has TCP and RAW")
    #     if "HTTP" in packet["Raw"].load.decode("utf-8", errors="ignore"):
    #         print("HTTP in Raw")
    #         print(packet.summary())
    #         # Extract the HTTP request data
    #         src_ip = packet["IP"].src
    #         dst_ip = packet["IP"].dst
    #         src_port = packet["TCP"].sport
    #         dst_port = packet["TCP"].dport
    #         http_data = packet["Raw"].load.decode("utf-8", errors="ignore")

    #         print(
    #             f"HTTP Request from {src_ip}:{src_port} to {dst_ip}:{dst_port}:\n{http_data}\n"
    #         )
    #     else:
    #         print(packet)


def main():
    try:
        print("Sniffing packets on your LAN. Press Ctrl+C to stop.")
        sniff(prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped.")
        sys.exit(0)
    except PermissionError:
        print("Error: You need to run this program with administrator/root privileges.")
        sys.exit(1)


if __name__ == "__main__":
    if os.name != "posix":
        print("Warning: This program is designed to run on Unix-like systems.")
    main()
