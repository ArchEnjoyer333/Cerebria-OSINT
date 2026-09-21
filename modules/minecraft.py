import asyncio
import json
import ipaddress
import re
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple
from .base import BaseModule


class MinecraftScannerModule(BaseModule):
    module_id = "minecraft_scanner"
    name = "Minecraft Scanner"
    tag = "MC"
    input_placeholder = "Enter domain, IP:port, or CIDR (e.g. mc.hypixel.net, 1.1.1.1:25565)..."
    description = "High-performance OSINT scanner discovering Minecraft server instances, player counts, and MOTD telemetry"

    def validate_target(self, target: str) -> Tuple[bool, str]:
        target = target.strip()
        host = target.split(":")[0]

        # IP
        try:
            ipaddress.ip_address(host)
            return True, ""
        except ValueError:
            pass

        # CIDR
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 65536:
                return False, "Subnet range is too large. Maximum supported subnet is /16."
            return True, ""
        except ValueError:
            pass

        # Домен
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if re.match(domain_pattern, host):
            return True, ""

        return False, "Target must be a valid domain, IP:port, or CIDR range."

    def _pack_varint(self, val: int) -> bytes:
        total = b""
        while True:
            byte = val & 0x7F
            val >>= 7
            if val != 0:
                byte |= 0x80
            total += bytes([byte])
            if val == 0:
                break
        return total

    async def _read_varint(self, reader: asyncio.StreamReader) -> int:
        val = 0
        for i in range(5):
            byte = await reader.readexactly(1)
            b = byte[0]
            val |= (b & 0x7F) << (7 * i)
            if not (b & 0x80):
                return val
        raise ValueError("VarInt too long")

    def _clean_motd(self, raw_description: Any) -> str:
        if isinstance(raw_description, str):
            return re.sub(r"§[0-9a-fk-or]|&[0-9a-fk-or]", "", raw_description).strip()
        elif isinstance(raw_description, dict):
            text = raw_description.get("text", "")
            for extra in raw_description.get("extra", []):
                if isinstance(extra, dict):
                    text += extra.get("text", "")
                elif isinstance(extra, str):
                    text += extra
            return re.sub(r"§[0-9a-fk-or]|&[0-9a-fk-or]", "", text).strip()
        elif isinstance(raw_description, list):
            return " ".join([self._clean_motd(x) for x in raw_description])
        return str(raw_description) if raw_description else "No MOTD"

    async def _raw_slp_ping(self, host: str, port: int = 25565, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        """Нативный асинхронный протокольный пинг Minecraft SLP."""
        start_time = time.time()
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)

            # 1. Формирование Handshake Packet (Protocol 47 = 1.8+, универсальный для пинга)
            host_bytes = host.encode("utf-8")
            packet_data = (
                b"\x00"  # Packet ID: Handshake
                + self._pack_varint(47)  # Protocol Version
                + self._pack_varint(len(host_bytes))
                + host_bytes
                + struct.pack(">H", port)
                + b"\x01"  # Next state: 1 (Status)
            )
            handshake = self._pack_varint(len(packet_data)) + packet_data

            # 2. Status Request Packet
            status_request = b"\x01\x00"

            # Отправка
            writer.write(handshake + status_request)
            await writer.drain()

            # Чтение ответа
            _ = await asyncio.wait_for(self._read_varint(reader), timeout=timeout)  # Packet length
            packet_id = await self._read_varint(reader)
            if packet_id != 0x00:
                writer.close()
                await writer.wait_closed()
                return None

            json_len = await self._read_varint(reader)
            raw_json_bytes = await asyncio.wait_for(reader.readexactly(json_len), timeout=timeout)

            latency = round((time.time() - start_time) * 1000, 1)

            writer.close()
            await writer.wait_closed()

            data = json.loads(raw_json_bytes.decode("utf-8", errors="replace"))

            players_data = data.get("players", {})
            version_data = data.get("version", {})

            player_sample = []
            if "sample" in players_data and isinstance(players_data["sample"], list):
                player_sample = [p.get("name", "") for p in players_data["sample"] if isinstance(p, dict) and p.get("name")]

            motd = self._clean_motd(data.get("description", ""))

            return {
                "host": host,
                "port": port,
                "version": version_data.get("name", "Unknown"),
                "protocol": version_data.get("protocol", 0),
                "players_online": players_data.get("online", 0),
                "players_max": players_data.get("max", 0),
                "player_sample": player_sample,
                "motd": motd if motd else "A Minecraft Server",
                "latency_ms": latency
            }
        except Exception:
            return None

    async def _tcp_probe(self, ip: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> Optional[str]:
        async with semaphore:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return ip
            except Exception:
                return None

    async def run(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        target = target.strip()
        timeout_ping = float(config.get("ping_timeout", 4.5))
        timeout_probe = float(config.get("probe_timeout", 1.2))
        max_concurrency = int(config.get("max_concurrency", 500))

        # Одиночный домен или IP:port
        if "/" not in target:
            port = 25565
            host = target
            if ":" in target:
                parts = target.split(":")
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    port = 25565

            res = await self._raw_slp_ping(host, port, timeout_ping)
            discovered_servers = [res] if res else []
            active_servers = [s for s in discovered_servers if s["players_online"] > 0]
            total_players = sum(s["players_online"] for s in discovered_servers)

            return {
                "metrics": {
                    "Target Host": target,
                    "Resolved Endpoint": f"{host}:{port}",
                    "Open Status": "Verified Online" if res else "Unreachable / Filtered",
                    "Minecraft Instances": len(discovered_servers),
                    "Populated Servers": len(active_servers),
                    "Total Players Tracked": total_players
                },
                "raw": {
                    "target": target,
                    "total_scanned_hosts": 1,
                    "open_ports_count": 1 if res else 0,
                    "total_servers_found": len(discovered_servers),
                    "active_servers_count": len(active_servers),
                    "total_players_online": total_players,
                    "servers": discovered_servers
                }
            }

        # CIDR подсеть
        network = ipaddress.ip_network(target, strict=False)
        hosts_to_scan = [str(ip) for ip in network.hosts()]

        semaphore = asyncio.Semaphore(max_concurrency)
        probe_tasks = [self._tcp_probe(ip, 25565, timeout_probe, semaphore) for ip in hosts_to_scan]
        probe_results = await asyncio.gather(*probe_tasks)
        open_ips = [ip for ip in probe_results if ip is not None]

        ping_tasks = [self._raw_slp_ping(ip, 25565, timeout_ping) for ip in open_ips]
        ping_results = await asyncio.gather(*ping_tasks)
        discovered_servers = [s for s in ping_results if s is not None]

        active_servers = [s for s in discovered_servers if s["players_online"] > 0]
        total_players = sum(s["players_online"] for s in discovered_servers)

        return {
            "metrics": {
                "Target Subnet": target,
                "Hosts Scanned": len(hosts_to_scan),
                "Open Port 25565": len(open_ips),
                "Minecraft Instances": len(discovered_servers),
                "Populated Servers": len(active_servers),
                "Total Players Tracked": total_players
            },
            "raw": {
                "target": target,
                "total_scanned_hosts": len(hosts_to_scan),
                "open_ports_count": len(open_ips),
                "total_servers_found": len(discovered_servers),
                "active_servers_count": len(active_servers),
                "total_players_online": total_players,
                "servers": discovered_servers
            }
        }
