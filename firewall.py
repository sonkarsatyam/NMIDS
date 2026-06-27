import subprocess

def block_ip(ip):

    print("BLOCKING:", ip)

    try:

        result = subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=NMIDS_Block_{ip}",
                "dir=in",
                "action=block",
                f"remoteip={ip}"
            ],
            capture_output=True,
            text=True
        )

        print("RETURN CODE:", result.returncode)
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)

        return result.returncode == 0

    except Exception as e:

        print("FIREWALL ERROR:", e)
        return False
    
def unblock_ip(ip):

    try:

        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name=NMIDS_Block_{ip}"
            ],
            check=True
        )

        return True

    except Exception as e:

        print(e)
        return False