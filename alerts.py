def check_alerts(results):

    alerts = []

    for port, service, banner in results:

        if port == 21:
            alerts.append(
                "FTP detected - check anonymous login"
            )

        elif port == 23:
            alerts.append(
                "TELNET detected - insecure protocol"
            )

        elif port == 445:
            alerts.append(
                "SMB exposed - verify access control"
            )

        elif port == 3389:
            alerts.append(
                "RDP exposed - verify remote access policy"
            )

        elif port == 22:
            alerts.append(
                "SSH detected - verify authentication settings"
            )

    return alerts