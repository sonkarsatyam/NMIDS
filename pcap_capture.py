from scapy.all import wrpcap

captured_packets = []

capture_enabled = False


def start_capture():

    global capture_enabled

    capture_enabled = True


def stop_capture():

    global capture_enabled

    capture_enabled = False


def add_packet(packet):

    if capture_enabled:

        captured_packets.append(packet)


def save_pcap(filename="capture.pcap"):

    if captured_packets:

        wrpcap(
            filename,
            captured_packets
        )

        return filename

    return None