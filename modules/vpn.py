import ipaddress
from typing import Any, Dict
import httpx
from .base import BaseModule


class VpnDetectorModule(BaseModule):
    module_id = "vpn_detector"
    name = "VPN & Proxy"
    tag = "SEC"
    input_placeholder = "Enter IPv4 address (e.g. 1.1.1.1, 146.70.113.5)..."
    description = "Detects commercial VPNs, Proxies, and Datacenter IPs"

    def validate_target(self, target: str) -> tuple[bool, str]:
        try:
            ipaddress.ip_address(target.strip())
            return True, ""
        except ValueError:
            return False, "Target must be a valid IP address"

    async def run(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        target = target.strip()

        is_proxy = False
        is_hosting = False
        org = "Unknown"
        isp = "Unknown"
        country = "N/A"
        asn = "N/A"
        risk_level = "LOW"
        provider_used = "None"

        # Расширенные словари эвристики
        vpn_keywords = ["vpn", "mullvad", "nordvpn", "proton", "expressvpn", "surfshark", "cyberghost", "private internet access", "hide.me", "ipvanish", "wireguard"]
        hosting_keywords = ["hosting", "datacenter", "cloud", "server", "colocation", "ovh", "digitalocean", "hetzner", "linode", "aws", "amazon", "azure", "google cloud", "vps", "host", "contabo"]

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }

        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, headers=headers) as client:
            # Попытка 1: ip-api.com
            try:
                url = f"http://ip-api.com/json/{target}?fields=status,message,country,isp,org,as,proxy,hosting"
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

                if data.get("status") == "success":
                    is_proxy = data.get("proxy", False)
                    is_hosting = data.get("hosting", False)
                    org = data.get("org") or "Unknown"
                    isp = data.get("isp") or "Unknown"
                    asn = data.get("as") or "N/A"
                    country = data.get("country", "N/A")
                    provider_used = "ip-api.com"
                else:
                    raise ValueError("ip-api query rejected")
            except Exception:
                # Попытка 2: Фоллбэк на ipwhois.app, если первый упал по таймауту
                try:
                    url2 = f"https://ipwhois.app/json/{target}"
                    resp2 = await client.get(url2)
                    resp2.raise_for_status()
                    data2 = resp2.json()

                    if data2.get("success") is not False:
                        org = data2.get("org") or "Unknown"
                        isp = data2.get("isp") or "Unknown"
                        asn = data2.get("asn") or "N/A"
                        country = data2.get("country", "N/A")
                        provider_used = "ipwhois.app"
                    else:
                        raise ValueError("ipwhois.app query rejected")
                except Exception as e:
                    raise RuntimeError(f"All network routes exhausted. Providers unavailable: {str(e)}")

        # Эвристический анализ названий (работает независимо от того, какой API ответил)
        combined_text = f"{org} {isp} {asn}".lower()

        for kw in vpn_keywords:
            if kw in combined_text:
                is_proxy = True
                break

        for kw in hosting_keywords:
            if kw in combined_text:
                is_hosting = True
                break

        # Вычисление уровня угрозы
        if is_proxy:
            risk_level = "HIGH (VPN/Proxy)"
        elif is_hosting:
            risk_level = "MEDIUM (Datacenter)"

        return {
            "metrics": {
                "Target IP": target,
                "Risk Level": risk_level,
                "VPN / Proxy": "YES" if is_proxy else "No",
                "Datacenter": "YES" if is_hosting else "No",
                "ISP / Org": f"{isp}",
                "Country": country,
            },
            "raw": {
                "ip": target,
                "is_vpn_or_proxy": is_proxy,
                "is_datacenter": is_hosting,
                "risk_level": risk_level,
                "isp": isp,
                "organization": org,
                "asn": asn,
                "country": country,
                "api_provider": provider_used
            }
        }
