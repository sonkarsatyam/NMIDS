from collections import defaultdict
import time

SCAN_WINDOW = 10          # seconds
PORT_THRESHOLD = 10       # unique ports

scan_tracker = defaultdict(
    lambda: {
        "ports": set(),
        "first_seen": 0,
        "alerted": False
    }
)


def detect_port_scan(src_ip, dst_port):

    current_time = time.time()

    host = scan_tracker[src_ip]

    # First packet
    if host["first_seen"] == 0:
        host["first_seen"] = current_time

    # Window expired -> reset
    if current_time - host["first_seen"] > SCAN_WINDOW:

        host["ports"].clear()
        host["first_seen"] = current_time
        host["alerted"] = False

    # Add destination port
    host["ports"].add(dst_port)

    # Already reported
    if host["alerted"]:
        return None

    # Detection
    if len(host["ports"]) >= PORT_THRESHOLD:

        host["alerted"] = True

        return (
            f"⚠ PORT SCAN DETECTED | "
            f"{src_ip} | "
            f"{len(host['ports'])} Ports"
        )

    return None