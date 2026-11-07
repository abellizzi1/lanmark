import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator


class Target(BaseModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    address: str = Field(min_length=1, max_length=512)
    kind: Literal["gateway", "isp", "dns", "http"]
    module: Literal["icmp_ipv4", "dns_udp", "http_2xx"]

    @model_validator(mode="after")
    def protocol(self):
        expected = {"gateway": "icmp_ipv4", "isp": "icmp_ipv4", "dns": "dns_udp", "http": "http_2xx"}
        if self.module != expected[self.kind]:
            raise ValueError("Target kind and blackbox module must match")
        return self


class Settings(BaseModel):
    interval_seconds: int = Field(default=30, ge=10, le=3600)
    offline_after_seconds: int = Field(default=180, ge=60)
    retention_days: int = Field(default=30, ge=1, le=365)
    baseline_samples: int = Field(default=120, ge=30, le=2000)
    expected_agents: list[str] = Field(default_factory=lambda: ["home-wifi"])
    targets: list[Target] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def unique_names(self):
        if len({t.name for t in self.targets}) != len(self.targets):
            raise ValueError("Target names must be unique")
        return self


def load_settings() -> Settings:
    path = os.getenv("CONFIG_FILE", "/etc/lanmark/lanmark.yaml")
    return Settings(**(yaml.safe_load(Path(path).read_text()) or {})) if Path(path).exists() else Settings()
