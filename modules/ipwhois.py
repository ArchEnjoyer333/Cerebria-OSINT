import ipaddress
from typing import Any, Dict
import httpx
from .base import BaseModule


class IpWhoisModule(BaseModule):
    module_id = "ipwhois"
    name = "IpWhoIs"
    tag = "RDAP"
    input_placeholder = "Enter IPv4 / IPv6 (e.g. 1.1.1.1, 8.8.8.8)..."
    description = "Autonomous System, ISP, and Geo telemetry"

    def validate_target(self, target: str) -> tuple[bool, str]:
        try:
            ipaddress.ip_address(target.strip())
            return True, ""
        except ValueError:
            return False, "Target must be a valid IPv4 or IPv6 address"

    # Провайдер 1: Основной
    async def _fetch_ipwhois_app(self, client: httpx.AsyncClient, target: str) -> Dict[str, Any]:
        url = f"https://ipwhois.app/json/{target}"
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
        if data.get("success") is False:
            raise ValueError(data.get("message") or "ipwhois.app rejected query")
        return data

    # Провайдер 2: Быстрый резерв
    async def _fetch_ip_api(self, client: httpx.AsyncClient, target: str) -> Dict[str, Any]:
        url = f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "fail":
            raise ValueError(data.get("message") or "ip-api.com rejected query")

        return {
            "ip": data.get("query"),
            "type": "IPv6" if ":" in target else "IPv4",
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "asn": (data.get("as") or "").split(" ")[0] if data.get("as") else "N/A",
            "org": data.get("org") or data.get("isp"),
            "isp": data.get("isp"),
            "timezone": data.get("timezone"),
            "timezone_gmt": "",
        }

    # Провайдер 3: Глубокий резерв
    async def _fetch_freeipapi(self, client: httpx.AsyncClient, target: str) -> Dict[str, Any]:
        url = f"https://freeipapi.com/api/json/{target}"
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()

        return {
            "ip": target,
            "type": "IPv6" if ":" in target else "IPv4",
            "country": data.get("countryName"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("cityName"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "asn": "N/A", # freeipapi не отдает ASN бесплатно
            "org": "N/A",
            "isp": "N/A",
            "timezone": data.get("timeZone"),
            "timezone_gmt": "",
        }

    async def run(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        target = target.strip()
        data = None
        errors = []

        # Универсальный заголовок, чтобы не блочили защитой от ботов
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }

        # Таймаут увеличен до 10 секунд на каждый запрос
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, headers=headers) as client:
            try:
                data = await self._fetch_ipwhois_app(client, target)
            except Exception as e1:
                errors.append(f"Provider 1 failed: {type(e1).__name__}")

                try:
                    data = await self._fetch_ip_api(client, target)
                except Exception as e2:
                    errors.append(f"Provider 2 failed: {type(e2).__name__}")

                    try:
                        data = await self._fetch_freeipapi(client, target)
                    except Exception as e3:
                        errors.append(f"Provider 3 failed: {type(e3).__name__}")
                        # Если упали все три сервиса — выводим ошибку в UI
                        raise RuntimeError(f"All network routes exhausted. Log: {' | '.join(errors)}")

        lat = data.get("latitude")
        lon = data.get("longitude")
        coords = f"{lat}, {lon}" if lat is not None and lon is not None else "N/A"

        country = data.get("country", "N/A")
        code = data.get("country_code", "")
        country_str = f"{country} ({code})" if code else country

        location_parts = [data.get("city"), data.get("region"), country_str]
        location_str = ", ".join(filter(None, location_parts)) or "N/A"

        tz = data.get("timezone", "")
        tz_gmt = data.get("timezone_gmt", "")
        tz_str = f"{tz} (GMT {tz_gmt})".strip() if (tz and tz_gmt) else (tz or tz_gmt or "N/A")

        return {
            "metrics": {
                "Target IP": target,
                "Autonomous System": data.get("asn") or "N/A",
                "Organization": data.get("org") or "N/A",
                "ISP Provider": data.get("isp") or "N/A",
                "Location": location_str,
                "Coordinates": coords,
                "Timezone": tz_str,
            },
            "raw": data,
        }
