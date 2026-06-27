import platform
import socket
import psutil


def get_system_info():

    hostname = socket.gethostname()

    ip = socket.gethostbyname(hostname)

    cpu = psutil.cpu_percent(interval=0.5)

    ram = psutil.virtual_memory().percent

    os_name = platform.system() + " " + platform.release()

    return {

        "Hostname": hostname,

        "OS": os_name,

        "CPU": f"{cpu}%",

        "RAM": f"{ram}%",

        "IP": ip

    }