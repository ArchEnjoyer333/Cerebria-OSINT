import asyncio
import re
import socket
from typing import Any, Dict, List, Set, Tuple
import httpx
from .base import BaseModule


class SubdomainReconModule(BaseModule):
    module_id = "subdomains"
    name = "Subdomains"
    tag = "DOM"
    input_placeholder = "Enter target domain (e.g. shodan.io, github.com)..."
    description = "Hybrid subdomain discovery: Direct Async DNS probing + Certificate Transparency"

    # Топ-35 наиболее частых поддоменов для мгновенного сетевого резолвинга
    TOP_SUBDOMAINS = [
        "www", "api", "auth", "dev", "staging", "admin", "mail", "webmail",
        "app", "portal", "vpn", "remote", "beta", "status", "test", "demo",
        "corp", "secure", "cdn", "cloud", "dns", "ns1", "ns2", "smtp",
        "static", "assets", "monitor", "gitlab", "jira", "docs", "help",
        "account", "login", "sso", "dashboard"
    ]

    def validate_target(self, target: str) -> Tuple[bool, str]:
        cleaned = self._clean_domain(target)
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if re.match(domain_pattern, cleaned):
            return True, ""
        return False, "Target must be a valid domain name (e.g., example.com)"

    def _clean_domain(self, target: str) -> str:
        target = target.strip().lower()
        target = re.sub(r"^https?://", "", target)
        return target.split("/")[0].split(":")[0]

    async def _resolve_subdomain(self, sub: str, domain: str) -> str | None:
        full_host = f"{sub}.{domain}"
        loop = asyncio.get_running_loop()
        try:
            # Асинхронное обращение к системному DNS резолверу
            await loop.getaddrinfo(full_host, None, family=socket.AF_INET)
            return full_host
        except Exception:
            return None

    async def _fetch_crtsh(self, client: httpx.AsyncClient, domain: str) -> Tuple[Set[str], List[str]]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = await client.get(url, timeout=5.0)
            if resp.status_code != 200:
                return set(), []
            data = resp.json()
            subs = set()
            issuers = set()
            for entry in data:
                issuer_name = entry.get("issuer_name", "")
                if issuer_name:
                    match = re.search(r"O=([^,]+)", issuer_name)
                    if match:
                        issuers.add(match.group(1).strip().strip('"'))

                name_val = entry.get("name_value", "")
                for name in name_val.split("\n"):
                    name = name.strip().lower()
                    name = re.sub(r"^\*\.", "", name)
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name)
            return subs, list(issuers)
        except Exception:
            return set(), []

    async def _fetch_hackertarget(self, client: httpx.AsyncClient, domain: str) -> Set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            resp = await client.get(url, timeout=4.0)
            if resp.status_code != 200 or "error" in resp.text.lower():
                return set()
            subs = set()
            for line in resp.text.split("\n"):
                if "," in line:
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(f".{domain}") or host == domain:
                        subs.add(host)
            return subs
        except Exception:
            return set()

    async def run(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._clean_domain(target)
        all_subs: Set[str] = set()
        all_issuers: List[str] = []
        sources: List[str] = []

        # 1. Параллельный DNS-скан по системным сокетам (работает всегда без rate-limit)
        dns_tasks = [self._resolve_subdomain(sub, domain) for sub in self.TOP_SUBDOMAINS]
        dns_results = await asyncio.gather(*dns_tasks)

        found_by_dns = {host for host in dns_results if host is not None}
        if found_by_dns:
            all_subs.update(found_by_dns)
            sources.append("Direct DNS Probing")

        # 2. Попытка собрать расширенные данные из внешних CT-логов
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*"
        }

        async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
            crt_subs, issuers = await self._fetch_crtsh(client, domain)
            if crt_subs:
                all_subs.update(crt_subs)
                all_issuers.extend(issuers)
                sources.append("crt.sh")

            if len(all_subs) < 5:
                ht_subs = await self._fetch_hackertarget(client, domain)
                if ht_subs:
                    all_subs.update(ht_subs)
                    sources.append("HackerTarget")

        sorted_subs = sorted(list(all_subs))
        provider_name = " + ".join(sources) if sources else "Direct DNS"

        return {
            "metrics": {
                "Target Domain": domain,
                "Discovered Hosts": len(sorted_subs),
                "Active Sources": len(sources),
                "Discovery Engine": provider_name
            },
            "raw": {
                "domain": domain,
                "total_count": len(sorted_subs),
                "subdomains": sorted_subs,
                "issuers": list(set(all_issuers))[:5],
                "provider": provider_name
            }
        }
