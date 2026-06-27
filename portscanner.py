import socket
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed
)


def scan_port(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        result = sock.connect_ex(
            (target, port)
        )

        sock.close()

        if result == 0:

            try:

                service = socket.getservbyport(
                    port
                )

            except:

                service = "Unknown"

            banner = ""

            try:

                banner_sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )

                banner_sock.settimeout(2)

                banner_sock.connect(
                    (target, port)
                )

                banner = banner_sock.recv(
                    1024
                ).decode(
                    errors="ignore"
                ).strip()

                banner_sock.close()

            except:

                banner = ""

            return (
                port,
                service,
                banner
            )

    except:
        pass

    return None


def scan_target(
    target,
    start_port,
    end_port,
    progress_callback=None,
    scanned_callback=None
):

    open_ports = []

    ports = list(
        range(
            start_port,
            end_port + 1
        )
    )

    total_ports = len(ports)

    if total_ports == 0:
        return []

    scanned = 0

    with ThreadPoolExecutor(
        max_workers=100
    ) as executor:

        future_map = {
            executor.submit(
                scan_port,
                target,
                port
            ): port
            for port in ports
        }

        for future in as_completed(
            future_map
        ):

            scanned += 1

            import time
            time.sleep(0.02)

            if scanned_callback:

                scanned_callback(
                    scanned
                )

            percentage = int(
                (scanned / total_ports)
                * 100
            )

            if progress_callback:

                progress_callback(
                    percentage
                )

            try:

                result = future.result()

                if result:

                    open_ports.append(
                        result
                    )

            except:
                pass

    return sorted(
        open_ports,
        key=lambda x: x[0]
    )