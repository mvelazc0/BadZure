import os
import requests


def get_public_ip():
    """Return the operator's public IP, used to lock foothold NSG rules and App
    Service access restrictions down to the operator (see terraform/main.tf's
    var.public_ip). Resolution order:

      1. BADZURE_PUBLIC_IP env var — an explicit override for air-gapped/proxied
         environments where the ipify call can't reach out (or to pin a known IP).
      2. A live lookup against api64.ipify.org.

    Returns the IP string, or None if it could not be determined. Callers MUST treat
    None as fatal before deploy: a null flows into `${var.public_ip}/32` and detonates
    mid-apply with "Cannot include a null value in a string template".
    """
    override = os.environ.get("BADZURE_PUBLIC_IP", "").strip()
    if override:
        return override

    try:
        response = requests.get("https://api64.ipify.org?format=json", timeout=10)
        response.raise_for_status()
        ip = response.json()["ip"]
        return ip
    except requests.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return None
