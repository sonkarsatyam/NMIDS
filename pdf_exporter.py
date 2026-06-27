from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def export_pdf(
    filename,
    target,
    results,
    alerts,
    scan_time
):

    doc = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "NMIDS Scan Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            f"Target: {target}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"Scan Time: {scan_time}",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            "Open Ports",
            styles["Heading2"]
        )
    )

    for port, service, banner in results:

        content.append(
            Paragraph(
                f"{port}/tcp - {service} - {banner}",
                styles["Normal"]
            )
        )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            "Alerts",
            styles["Heading2"]
        )
    )

    for alert in alerts:

        content.append(
            Paragraph(
                alert,
                styles["Normal"]
            )
        )

    doc.build(content)