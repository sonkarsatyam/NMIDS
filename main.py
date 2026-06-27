from portscanner import scan_target
from logger import save_port_scan
from alerts import check_alerts
import time
from alerts import check_alerts

print("=" * 50)
print("NETWORK MONITORING & PORT SCANNER")
print("=" * 50)

target = input("Target IP: ")

start_port = int(
    input("Start Port: ")
)

end_port = int(
    input("End Port: ")
)

start_time = time.time()

results = scan_target(
    target,
    start_port,
    end_port
)

print("\nOpen Ports Found:\n")

if len(results) == 0:
    print("No Open Ports Found")

else:

    for port, service in results:

        print(
            f"{port}/tcp ---> {service}"
        )

save_port_scan(
    target,
    results
)

alerts = check_alerts(
    results
)

if alerts:

    print("\nALERTS:\n")

    for alert in alerts:

        print(alert)

print(
    f"\nScan Completed In "
    f"{round(time.time() - start_time, 2)} Seconds"
)

print(
    "\nResults Saved To portscan_log.txt"
)