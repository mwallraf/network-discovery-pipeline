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
