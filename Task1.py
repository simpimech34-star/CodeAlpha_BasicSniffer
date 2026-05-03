from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import random

def generate_fake_ip():
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


def packet_analyzer(packet):

    print("\n==============================")

    if packet.haslayer(IP):

        fake_source_ip = generate_fake_ip()
        fake_destination_ip = generate_fake_ip()

        print("Source IP      :", fake_source_ip)
        print("Destination IP :", fake_destination_ip)

        # Protocol detection
        if packet.haslayer(TCP):
            print("Protocol       : TCP")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print("Protocol       : Other")

        # Payload check
        if packet.haslayer(Raw):

            payload = packet[Raw].load

            if payload:
                try:
                    decoded_payload = payload.decode(
                        "utf-8",
                        errors="ignore"
                    )
                    print("Payload Data   :", decoded_payload[:100])

                except:
                    print("Payload Data   : Binary data")

        else:
            print("Payload Data   : No payload")

    print("==============================")


print("Starting Network Sniffer...")
print("Fake IP mode enabled.")
print("Press CTRL + C to stop.\n")

sniff(
    filter="tcp or udp or icmp",
    prn=packet_analyzer,
    store=False
)
