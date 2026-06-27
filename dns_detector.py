from collections import defaultdict

dns_records = defaultdict(set)


def detect_dns_spoof(domain, ip):

    if ip not in dns_records[domain]:

        dns_records[domain].add(ip)

    if len(dns_records[domain]) > 10:

        return (
            f"⚠ Possible DNS Spoofing: "
            f"{domain}"
        )

    return None