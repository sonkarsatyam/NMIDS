from collections import defaultdict
import time
from alert_manager import should_alert

syn_tracker = defaultdict(list)


def detect_syn_flood(src_ip):

    current_time = time.time()

    syn_tracker[src_ip].append(
        current_time
    )

    recent_syns = [

        ts

        for ts in syn_tracker[src_ip]

        if current_time - ts < 10
    ]

    syn_tracker[src_ip] = recent_syns

    if len(recent_syns) > 20:

        if should_alert(
            f"SYN_{src_ip}"
        ):

            return (
                f"⚠ Possible SYN Flood from "
                f"{src_ip}"
            )

    return None