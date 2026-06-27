from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet

from datetime import datetime


def generate_incident_report(
    filename,
    threat_stats,
    talkers
):

    doc = SimpleDocTemplate(
        filename
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "NMIDS Incident Report",
            styles["Title"]
        )
    )

    content.append(
        Paragraph(
            f"Generated: {datetime.now()}",
            styles["Normal"]
        )
    )

    content.append(
        Spacer(1, 20)
    )

    content.append(
        Paragraph(
            "Threat Statistics",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            f"Port Scans: {threat_stats['port_scan']}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"ARP Spoofs: {threat_stats['arp']}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"DNS Alerts: {threat_stats['dns']}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"SYN Floods: {threat_stats['syn']}",
            styles["Normal"]
        )
    )

    content.append(
        Spacer(1, 20)
    )

    content.append(
        Paragraph(
            "Top Talkers",
            styles["Heading2"]
        )
    )

    sorted_ips = sorted(
        talkers.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for ip, count in sorted_ips[:10]:

        content.append(
            Paragraph(
                f"{ip} : {count} packets",
                styles["Normal"]
            )
        )

    doc.build(content)