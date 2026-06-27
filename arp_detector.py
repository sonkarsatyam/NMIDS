arp_table = {}

def detect_arp_spoof(ip, mac):

    if mac == "00:00:00:00:00:00":
        return None

    if ip not in arp_table:
        arp_table[ip] = mac
        return None

    if arp_table[ip] != mac:
        return (
            f"⚠ ARP Spoofing Detected | "
            f"{ip} changed from "
            f"{arp_table[ip]} to {mac}"
        )

    return None