from ndp.result import StepResult
from ndp.state import load_step_results, save_step_result


def test_roundtrip(tmp_path):
    save_step_result(tmp_path / "state", StepResult("parse", outputs={"devices": "/x.json"}))
    save_step_result(tmp_path / "state", StepResult("scan", error="boom"))
    results = load_step_results(tmp_path / "state")
    assert results["parse"]["outputs"] == {"devices": "/x.json"}
    assert results["scan"]["status"] == "failed"


def test_missing_dir_and_broken_file(tmp_path):
    assert load_step_results(tmp_path / "nope") == {}
    (tmp_path / "last-scan.json").write_text("{broken")
    assert load_step_results(tmp_path) == {}
