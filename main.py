from scapy.all import IP, TCP, UDP, ICMP
from scapy.packet import Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto

        if protocol == 6:  # TCP
            proto_name = "TCP"
            payload = packet[TCP].payload
        elif protocol == 17:  # UDP
            proto_name = "UDP"
            payload = packet[UDP].payload
        elif protocol == 1:  # ICMP
            proto_name = "ICMP"
            payload = packet[ICMP].payload
        else:
            proto_name = "Other"
            payload = ip_layer.payload

        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {proto_name}")
        print(f"Payload: {payload}")
        print("-" * 50)

# Mock packets
mock_tcp_packet = IP(src="192.168.0.1", dst="192.168.0.2")/TCP()/Raw(load="TCP Payload")
mock_udp_packet = IP(src="192.168.0.1", dst="192.168.0.2")/UDP()/Raw(load="UDP Payload")
mock_icmp_packet = IP(src="192.168.0.1", dst="192.168.0.2")/ICMP()/Raw(load="ICMP Payload")

# Process mock packets
packet_callback(mock_tcp_packet)
packet_callback(mock_udp_packet)
packet_callback(mock_icmp_packet)
from scapy.all import sniff, IP, TCP, UDP, ICMP
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto

        if protocol == 6:  # TCP
            proto_name = "TCP"
            payload = packet[TCP].payload
        elif protocol == 17:  # UDP
            proto_name = "UDP"
            payload = packet[UDP].payload
        elif protocol == 1:  # ICMP
            proto_name = "ICMP"
            payload = packet[ICMP].payload
        else:
            proto_name = "Other"
            payload = ip_layer.payload

        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {proto_name}")
        print(f"Payload: {payload}")
        print("-" * 50)
def start_sniffing(interface):
    print(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)
def main():
    interfaces = get_if_list()
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")

    interface_num = int(input("Enter the interface number to sniff on: "))
    interface = interfaces[interface_num]
    start_sniffing(interface)

if __name__ == "__main__":
    main()
