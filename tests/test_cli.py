import json

import pytest

from ndp.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("ndp ")


def test_step_is_required(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_exclude_without_inputs_fails_as_json(config_path, capsys):
    assert main(["-c", str(config_path), "exclude"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["step"] == "exclude" and "infra-routers.json" in out["error"]
