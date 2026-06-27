from scapy.all import AsyncSniffer
from pcap_capture import add_packet
from top_talkers import talkers
from arp_detector import detect_arp_spoof
from dns_detector import detect_dns_spoof
from syn_detector import detect_syn_flood
from threat_stats import threat_stats
from ids_rules import detect_port_scan
from traffic_stats import stats
from geoip import get_geo_info
from scapy.layers.inet import (
    IP,
    TCP,
    UDP,
    ICMP
)

from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
graph_packet_counter = 0
sniffer_instance = None

reported_malicious_ips = set()

malicious_ips = {
    "185.220.101.1",
    "45.95.147.236",
    "103.21.244.0",
    "10.42.94.115"
}


def start_sniffer(callback):

    print("START_SNIFFER FUNCTION")


    packet_counter = 0

    def packet_handler(packet):

        nonlocal packet_counter

        add_packet(packet)

        packet_counter += 1

        global graph_packet_counter

        graph_packet_counter += 1

        # ====================
        # Traffic Statistics
        # ====================

        if packet.haslayer(TCP):
            stats["TCP"] += 1

        elif packet.haslayer(UDP):
            stats["UDP"] += 1

        elif packet.haslayer(ICMP):
            stats["ICMP"] += 1

        elif packet.haslayer(ARP):
            stats["ARP"] += 1

        # ====================
        # IP Processing
        # ====================

        if packet.haslayer(IP):

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Threat Intel

            if src_ip in malicious_ips:

                if src_ip not in reported_malicious_ips:

                    print(
    "MALICIOUS DETECTED:",
    src_ip
)

                    reported_malicious_ips.add(src_ip)

                    geo = get_geo_info(src_ip)

                    callback(
                        f"[HIGH] Malicious IP | "
                        f"{src_ip} | "
                        f"{geo['country']}"
                    )

            # Top Talkers

            if src_ip not in talkers:

                talkers[src_ip] = 0

            talkers[src_ip] += 1

            # Packet Monitor

            if packet_counter % 100 == 0:

                if packet.haslayer(TCP):

                    callback(
                        f"TCP | {src_ip} -> {dst_ip}"
                    )

                elif packet.haslayer(UDP):

                    callback(
                        f"UDP | {src_ip} -> {dst_ip}"
                    )

                elif packet.haslayer(ICMP):

                    callback(
                        f"ICMP | {src_ip} -> {dst_ip}"
                    )

                else:

                    callback(
                        f"IP | {src_ip} -> {dst_ip}"
                    )

        # ====================
        # ARP Detection
        # ====================

        if packet.haslayer(ARP):

            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            if packet_counter % 100 == 0:

                callback(
                    f"ARP | {ip}"
                )

            alert = detect_arp_spoof(
                ip,
                mac
            )

            if alert:

                callback(alert)

        # ====================
        # DNS Detection
        # ====================

        if packet.haslayer(DNS):

            if packet.haslayer(IP):

                try:

                    if packet[DNS].ancount > 0:

                        domain = packet[DNS].qd.qname.decode(
                            errors="ignore"
                        )

                        resolved_ip = packet[DNS].an.rdata

                        alert = detect_dns_spoof(
                            domain,
                            str(resolved_ip)
                        )

                        if alert:

                            callback(alert)

                except:

                    pass

        # ====================
        # IDS Rules
        # ====================

        if packet.haslayer(IP) and packet.haslayer(TCP):

            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            flags = packet[TCP].flags

            # SYN Flood

            if "S" in str(flags):

                alert = detect_syn_flood(
                    src_ip
                )

                if alert:

                    callback(alert)

            # Port Scan

            alert = detect_port_scan(
                src_ip,
                dst_port
            )

            if alert:

                callback(alert)

            # Telnet

            if dst_port == 23:

                callback(
                    "⚠ TELNET Traffic Detected"
                )

            # SMB

            if dst_port == 445:

                callback(
                    "⚠ SMB Traffic Detected"
                )

    global sniffer_instance

    sniffer_instance = AsyncSniffer(
        prn=packet_handler,
        store=False
        )

    sniffer_instance.start()

    print("ASYNC SNIFFER STARTED")

def stop_sniffer():

    global sniffer_instance

    if sniffer_instance:

        sniffer_instance.stop()

        sniffer_instance = None