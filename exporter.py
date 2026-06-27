import csv
from datetime import datetime


def export_txt(target, results):

    filename = (
        f"scan_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        f".txt"
    )

    with open(filename, "w") as file:

        file.write(
            f"Target: {target}\n\n"
        )

        for port, service in results:

            file.write(
                f"{port}/tcp ---> {service}\n"
            )

    return filename


def export_csv(target, results):

    filename = (
        f"scan_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        f".csv"
    )

    with open(
        filename,
        "w",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow(
            ["Target", target]
        )

        writer.writerow([])

        writer.writerow(
            ["Port", "Service"]
        )

        for port, service in results:

            writer.writerow(
                [port, service]
            )

    return filename