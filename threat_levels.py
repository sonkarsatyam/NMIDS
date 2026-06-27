def get_threat_level(alert):

    alert = alert.lower()

    if "syn flood" in alert:
        return "CRITICAL"

    if "arp spoof" in alert:
        return "HIGH"

    if "port scan" in alert:
        return "MEDIUM"

    if "telnet" in alert:
        return "MEDIUM"

    if "smb" in alert:
        return "LOW"

    return "LOW"