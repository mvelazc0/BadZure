import requests

def get_public_ip():
    
    try:
        response = requests.get("https://api64.ipify.org?format=json")
        response.raise_for_status()
        ip = response.json()["ip"]
        return ip
    except requests.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return None