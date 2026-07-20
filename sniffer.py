from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

print("=" * 60)
print("        CodeAlpha - Basic Network Sniffer")
print("=" * 60)
print("Press CTRL + C to Stop Sniffing...\n")


def process_packet(packet):

    print("-" * 60)

    # Check if packet contains IP Layer
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")

        # Detect Protocol
        if packet.haslayer(TCP):
            print("Protocol       : TCP")

            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port : {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")

            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port : {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print(f"Protocol Number: {ip_layer.proto}")

        # Display Payload
        if packet.haslayer(Raw):

            try:
                payload = packet[Raw].load.decode(errors="ignore")
                print("\nPayload:")
                print(payload[:300])

            except:
                print("Payload : Unable to Decode")

    else:
        print("Non-IP Packet Captured")


print("\nStarting Packet Capture...\n")

sniff(prn=process_packet, store=False)