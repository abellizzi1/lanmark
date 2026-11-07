import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Device(StrictModel):
    mac: str = Field(pattern=r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    ip: str

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, value):
        if int(value[:2], 16) & 1 or value == "00:00:00:00:00:00":
            raise ValueError("A unicast device MAC is required")
        return value.lower()

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value):
        return str(ipaddress.IPv4Address(value))


class Sample(StrictModel):
    target: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    kind: Literal["gateway", "isp", "dns", "http"]
    success: bool
    latency_seconds: float | None = Field(default=None, ge=0, le=120)
    loss_ratio: float | None = Field(default=None, ge=0, le=1)
    jitter_seconds: float | None = Field(default=None, ge=0, le=120)


class Traffic(StrictModel):
    # Host interface throughput, not total LAN or per-device usage.
    interface: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,32}$")
    rx_bytes_per_second: float = Field(ge=0, le=1e12)
    tx_bytes_per_second: float = Field(ge=0, le=1e12)


class Scan(StrictModel):
    source: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    scan_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    scan_ok: bool
    devices: list[Device] = Field(default_factory=list, max_length=1024)
    samples: list[Sample] = Field(default_factory=list, max_length=32)
    traffic: Traffic | None = None


class Approval(StrictModel):
    approved: bool = True
    name: str = Field(default="", max_length=128)


class Alert(StrictModel):
    # Alertmanager sends additional envelope fields; retain only these fields.
    model_config = ConfigDict(extra="ignore")
    fingerprint: str = Field(pattern=r"^[a-fA-F0-9]{1,64}$")
    status: Literal["firing", "resolved"]
    labels: dict[str, str] = Field(max_length=32)
    annotations: dict[str, str] = Field(default_factory=dict, max_length=32)


class AlertBatch(BaseModel):
    alerts: list[Alert] = Field(max_length=100)
