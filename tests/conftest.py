import shutil
from pathlib import Path

import pytest

from ndp.config import load_config

FIXTURES = Path(__file__).parent / "fixtures"

CONFIG_TEMPLATE = """\
paths:
  output: {output}
  inputs: {inputs}
nautobot:
  device_roles: [PE]
  prefix_roles:
    INFRA_LOOPBACK: {{function: CORE}}
    CPE_P2P: {{function: CPE}}
    MGMT_LAN: {{function: DCN}}
exclude:
  mgmt_interfaces: [Loopback64500, Loopback0, Loopback1]
"""


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    shutil.copy(FIXTURES / "prefixes.json", inputs / "prefixes.json")
    path = tmp_path / "ndp.yaml"
    path.write_text(CONFIG_TEMPLATE.format(output=tmp_path / "out", inputs=inputs))
    return path


@pytest.fixture
def cfg(config_path: Path):
    return load_config(config_path)
