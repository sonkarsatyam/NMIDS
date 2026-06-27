from scapy.all import ARP, Ether, srp
import socket
import ipaddress
import psutil
from scapy.all import get_if_addr

import psutil
import ipaddress


def get_local_network():

    interfaces = psutil.net_if_addrs()

    for name, addrs in interfaces.items():

        # Sirf Wi-Fi ya Wireless interface use karo
        if "wi-fi" not in name.lower() and "wifi" not in name.lower():
            continue

        for addr in addrs:

            if addr.family == 2:   # AF_INET

                ip = addr.address

                print("Using Interface :", name)
                print("Using IP :", ip)

                network = ipaddress.IPv4Network(
                    ip + "/24",
                    strict=False
                )

                return str(network)

    return None


def discover_hosts():

    network = get_local_network()

    print("Scanning :", network)

    if network is None:
        return []

    network = get_local_network()

    print("Scanning Network :", network)

    arp = ARP(
        pdst=network
    )

    ether = Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    packet = ether / arp

    answered = srp(
        packet,
        timeout=2,
        verbose=False
    )[0]

    hosts = []

    for _, received in answered:

        hosts.append(
            (
                received.psrc,
                received.hwsrc
            )
        )

    hosts.sort(
        key=lambda x:
        tuple(
            map(
                int,
                x[0].split(".")
            )
        )
    )
    print(hosts)

    return hosts