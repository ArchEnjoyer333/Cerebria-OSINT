import asyncio
import ipaddress
import re
import time
from typing import Any, Dict, List
import nmap  # Требуется: pip install python-nmap
from .base import BaseModule


class PortScannerModule(BaseModule):
    module_id = "port_scanner"
    name = "Port Scanner"
    tag = "NET"
    input_placeholder = "Enter IPv4 or domain (e.g. 1.1.1.1, example.com)..."
    description = "Professional TCP scanning of Top-20 critical ports using Nmap engine"

    # Топ-20 самых частых и критичных портов
    TARGET_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
        135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
        3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
    }

    def validate_target(self, target: str) -> tuple[bool, str]:
        target = target.strip().lower()
        target = re.sub(r"^https?://", "", target).split("/")[0]

        # Проверяем IP
        try:
            ipaddress.ip_address(target)
            return True, ""
        except ValueError:
            pass

        # Проверяем домен
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if re.match(domain_pattern, target):
            return True, ""

        return False, "Target must be a valid IPv4 address or domain name"

    async def run(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        cleaned_target = target.strip().lower()
        cleaned_target = re.sub(r"^https?://", "", cleaned_target).split("/")[0]

        start_time = time.time()

        # Инициализируем сканер Nmap
        nm = nmap.PortScanner()

        # Превращаем список портов в строку вида "21,22,23..."
        ports_str = ",".join(map(str, self.TARGET_PORTS.keys()))

        # Запускаем Nmap в отдельном потоке, чтобы не блокировать асинхронный event loop asyncio
        # Аргументы:
        # -Pn (не пинговать хост перед сканированием)
        # -sS (быстрое и скрытное SYN-сканирование, требует прав admin/root)
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: nm.scan(hosts=cleaned_target, arguments=f"-Pn -sS -sV -p {ports_str}")
            )
        except Exception as e:
            # Если у пользователя нет прав root/admin, -sS может упасть.
            # В таком случае откатываемся на обычное TCP Connect сканирование (-sT)
            await loop.run_in_executor(
                None,
                lambda: nm.scan(hosts=cleaned_target, arguments=f"-Pn -sT -sV -p {ports_str}")
            )

        scan_duration = round(time.time() - start_time, 2)

        open_ports = []
        closed_ports = []
        open_port_ids = []

        # Парсим структурированные результаты, которые вернул Nmap
        if cleaned_target in nm.all_hosts():
            for proto in nm[cleaned_target].all_protocols():
                if proto == "tcp":
                    for port in nm[cleaned_target][proto].keys():
                        state = nm[cleaned_target][proto][port]["state"]

                        if state == "open":
                            # Берём имя сервиса, определенное Nmap, либо наше дефолтное
                            service = nm[cleaned_target][proto][port].get("name", self.TARGET_PORTS.get(port, "unknown")).upper()
                            open_ports.append(f"{port} ({service})")
                            open_port_ids.append(port)
                        else:
                            closed_ports.append(str(port))

        # Заполняем порты, которые Nmap вообще не вернул (значит они закрыты/отфильтрованы)
        for port in self.TARGET_PORTS.keys():
            if port not in open_port_ids and str(port) not in closed_ports:
                closed_ports.append(str(port))

        # Сортируем открытые порты по возрастанию
        open_ports.sort(key=lambda x: int(x.split()[0]))

        # Точная оценка уровня риска на основе реальных данных
        risk_level = "LOW"
        critical_ports = {22, 3389, 3306, 445}

        if set(open_port_ids).intersection(critical_ports):
            risk_level = "HIGH (Exposed Admin/DB)"
        elif open_port_ids:
            risk_level = "MEDIUM (Exposed Services)"

        return {
            "metrics": {
                "Target Host": cleaned_target,
                "Open Ports": len(open_ports),
                "Critical Risk": risk_level,
                "Scan Duration": f"{scan_duration} seconds"
            },
            "raw": {
                "host": cleaned_target,
                "total_scanned": len(self.TARGET_PORTS),
                "open_count": len(open_ports),
                "open_ports": open_ports,
                "closed_count": len(closed_ports),
                "risk_level": risk_level,
                "duration_sec": scan_duration
            }
        }
