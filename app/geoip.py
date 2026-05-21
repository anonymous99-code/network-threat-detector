import requests

def get_geo_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        res = requests.get(url, timeout=3)
        data = res.json()

        return {
            "country": data.get("country", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown"),
        }

    except:
        return {
            "country": "Unknown",
            "region": "Unknown",
            "isp": "Unknown",
            "org": "Unknown",
        }