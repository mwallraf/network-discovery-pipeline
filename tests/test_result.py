import json

from ndp.result import StepResult, now_local


def test_ok_without_warnings():
    result = StepResult("parse")
    assert result.status == "ok"
    assert result.exit_code == 0


def test_warning_status_and_exit_code():
    result = StepResult("parse", warnings=["something odd"])
    assert result.status == "warning"
    assert result.exit_code == 2


def test_error_wins_over_warnings():
    result = StepResult("scan", error="nmap failed", warnings=["x"])
    assert result.status == "failed"
    assert result.exit_code == 1


def test_to_json_contains_all_fields():
    result = StepResult("scan", counts={"hosts_up": 3}, outputs={"scan_xml": "/x.xml"})
    data = json.loads(result.to_json())
    assert data == {
        "step": "scan",
        "status": "ok",
        "error": None,
        "warnings": [],
        "counts": {"hosts_up": 3},
        "outputs": {"scan_xml": "/x.xml"},
        "started": "",
        "finished": "",
    }


def test_now_local_is_timezone_aware():
    assert now_local().tzinfo is not None
