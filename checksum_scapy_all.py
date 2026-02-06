from scapy.all import *

pcap_file = "checksum_capture2.pcapng"
packets = rdpcap(pcap_file)

print("\n===== CHECKSUM VALIDATION USING SCAPY (METHOD 3) =====\n")

for i, pkt in enumerate(packets, start=1):
    print(f"\nPacket {i}")
    print("-" * 60)

    # Ethernet
    if Ether in pkt:
        print("Ethernet:")
        print("  No checksum field (CRC handled by hardware)")

    # IPv4
    if IP in pkt:
        ip = pkt[IP]
        old = ip.chksum
        del ip.chksum
        new = IP(bytes(ip)).chksum
        print("IPv4:")
        print(f"  Original Checksum   : {hex(old)}")
        print(f"  Recomputed Checksum : {hex(new)}")
        print("  Status              :", "VALID" if old == new else "INVALID")

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        old = tcp.chksum
        del tcp.chksum
        new = TCP(bytes(tcp)).chksum
        print("TCP:")
        print(f"  Original Checksum   : {hex(old)}")
        print(f"  Recomputed Checksum : {hex(new)}")
        print("  Status              :", "VALID" if old == new else "INVALID")

    # UDP
    if UDP in pkt:
        udp = pkt[UDP]
        old = udp.chksum
        del udp.chksum
        new = UDP(bytes(udp)).chksum
        print("UDP:")
        print(f"  Original Checksum   : {hex(old)}")
        print(f"  Recomputed Checksum : {hex(new)}")
        print("  Status              :", "VALID" if old == new else "INVALID")

    # ICMP
    if ICMP in pkt:
        icmp = pkt[ICMP]
        old = icmp.chksum
        del icmp.chksum
        new = ICMP(bytes(icmp)).chksum
        print("ICMP:")
        print(f"  Original Checksum   : {hex(old)}")
        print(f"  Recomputed Checksum : {hex(new)}")
        print("  Status              :", "VALID" if old == new else "INVALID")

    # TLS (no checksum)
    if TCP in pkt and pkt[TCP].dport == 443:
        print("TLS:")
        print("  No checksum field (integrity handled by encryption/MAC)")
