import requests


def get_geo_info(ip):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3
        )

        data = response.json()

        if data["status"] == "success":

            return {
                "country": data["country"],
                "city": data["city"],
                "isp": data["isp"]
            }

    except:
        pass

    return {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown"
    }

if __name__ == "__main__":

    print(
        get_geo_info("8.8.8.8")
    )