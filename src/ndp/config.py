"""ndp.yaml: static rules, versioned in git. Secrets come from the environment."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

Port = Annotated[int, Field(ge=1, le=65535)]


class ConfigError(Exception):
    """The configuration is missing or invalid."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Paths(_Model):
    output: Path
    inputs: Path


class PrefixRole(_Model):
    function: str = ""
    note: str = ""


class Nautobot(_Model):
    device_roles: list[str] = Field(default_factory=list)
    # dict order is the management IP preference
    prefix_roles: dict[str, PrefixRole] = Field(min_length=1)

    @field_validator("prefix_roles", mode="before")
    @classmethod
    def _allow_bare_role(cls, value):
        # "ROLE:" without a mapping loads as None in YAML
        if isinstance(value, dict):
            return {key: ({} if val is None else val) for key, val in value.items()}
        return value


class Scanner(_Model):
    nmap_path: str = "nmap"
    snmp_timeout_ms: int = Field(default=4000, gt=0)
    timing: int = Field(default=4, ge=0, le=5)
    tcp_ports: list[Port] = Field(default_factory=lambda: [22, 23, 179], min_length=1)
    host_discovery_ports: list[Port] = Field(default_factory=lambda: [22, 23], min_length=1)


class Outputs(_Model):
    devices_json: bool = True
    legacy_csv: bool = True
    legacy_csv_communities: bool = True
    services_csv: bool = True


class Housekeeping(_Model):
    keep_days: int = Field(default=30, ge=1)
    owner: int | str | None = None
    group: int | str | None = None
    file_mode: str = "0664"
    dir_mode: str = "0775"

    @field_validator("file_mode", "dir_mode")
    @classmethod
    def _octal(cls, value: str) -> str:
        try:
            mode = int(value, 8)
        except ValueError:
            raise ValueError(f"not an octal mode: {value!r}") from None
        if not 0 <= mode <= 0o7777:
            raise ValueError(f"mode out of range: {value!r}")
        return value


class Exclude(_Model):
    # priority order; names are compared case-insensitively, spaces ignored
    mgmt_interfaces: list[str] = Field(default_factory=list)
    # a router that has not answered for longer keeps no excluded addresses
    stale_max_days: int = Field(default=30, ge=1)


class Config(_Model):
    paths: Paths
    nautobot: Nautobot
    scanner: Scanner = Field(default_factory=Scanner)
    outputs: Outputs = Field(default_factory=Outputs)
    housekeeping: Housekeeping = Field(default_factory=Housekeeping)
    exclude: Exclude = Field(default_factory=Exclude)

    @property
    def scans_dir(self) -> Path:
        return self.paths.output / "nmap"

    @property
    def state_dir(self) -> Path:
        return self.paths.output / "state"


def load_config(path: Path) -> Config:
    path = Path(path)
    try:
        text = path.read_text()
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: the top level must be a mapping")
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        lines = [f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}" for err in exc.errors()]
        raise ConfigError(f"invalid config {path}:\n  " + "\n  ".join(lines)) from None


def communities_from_env(env: Mapping[str, str] | None = None) -> list[str]:
    env = os.environ if env is None else env
    communities = [c.strip() for c in env.get("SNMP_COMMUNITIES", "").split(",") if c.strip()]
    if not communities:
        raise ConfigError("SNMP_COMMUNITIES is not set or empty")
    return communities
