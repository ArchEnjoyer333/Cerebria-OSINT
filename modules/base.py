from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class ModuleMetric(BaseModel):
    label: str
    value: Any


class ModuleInfo(BaseModel):
    id: str
    name: str
    tag: str
    placeholder: str
    description: str
    enabled: bool = True


class ScanResult(BaseModel):
    status: str = "OK"
    metrics: Dict[str, Any] = Field(default_factory=dict)
    raw: Dict[str, Any] = Field(default_factory=dict)
    pivots: Optional[List[Dict[str, str]]] = Field(default_factory=list)


class BaseModule(ABC):
    module_id: str
    name: str
    tag: str
    input_placeholder: str
    description: str

    @abstractmethod
    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Возвращает (is_valid, error_message)."""
        pass

    @abstractmethod
    async def run(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Исполнение логики модуля. Должно возвращать словарь с ключами 'metrics' и 'raw'."""
        pass

    def get_info(self, enabled: bool = True, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        override = override or {}
        return ModuleInfo(
            id=self.module_id,
            name=override.get("name", self.name),
            tag=override.get("tag", self.tag),
            placeholder=override.get("placeholder", self.input_placeholder),
            description=override.get("description", self.description),
            enabled=override.get("enabled", enabled),
        ).model_dump()
