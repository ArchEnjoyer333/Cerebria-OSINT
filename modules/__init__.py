from typing import Dict
from .base import BaseModule
from .ipwhois import IpWhoisModule
from .phonehlr import PhoneHlrModule
from .subdomain import SubdomainReconModule
from .vpn import VpnDetectorModule
from .port import PortScannerModule
from .minecraft import MinecraftScannerModule  # <-- Импорт

REGISTRY: Dict[str, BaseModule] = {
    IpWhoisModule.module_id: IpWhoisModule(),
    PhoneHlrModule.module_id: PhoneHlrModule(),
    SubdomainReconModule.module_id: SubdomainReconModule(),
    VpnDetectorModule.module_id: VpnDetectorModule(),
    PortScannerModule.module_id: PortScannerModule(),
    MinecraftScannerModule.module_id: MinecraftScannerModule(),  # <-- Регистрация
}
