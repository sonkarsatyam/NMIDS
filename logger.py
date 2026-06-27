from datetime import datetime

def save_port_scan(target, results):

    with open("portscan_log.txt", "a") as file:

        file.write("\n")
        file.write("=" * 60)
        file.write("\n")

        file.write(f"Target: {target}\n")
        file.write(f"Time: {datetime.now()}\n\n")

        for port, service in results:

            file.write(
                f"Port: {port} | Service: {service}\n"
            )