from ndp.compare import compare_csv, main

HEADER = "_key,hostname,function,mgmt_ip\n"


def test_compare(tmp_path, capsys):
    old = tmp_path / "old.csv"
    new = tmp_path / "new.csv"
    old.write_text(HEADER + "a,a,CPE,192.0.2.10\nb,b,DCN,192.0.2.2\nonly-old,x,,\n")
    new.write_text(HEADER + "a,a,CPE,192.0.2.9\nb,b,DCN,192.0.2.2\nonly-new,y,,\n")
    report = compare_csv(old, new)
    assert report["only_old"] == ["only-old"]
    assert report["only_new"] == ["only-new"]
    assert report["column_diffs"] == {"mgmt_ip": 1}
    assert report["examples"]["mgmt_ip"] == [("a", "192.0.2.10", "192.0.2.9")]
    assert main([str(old), str(new)]) == 0
    assert "mgmt_ip: 1 rows differ" in capsys.readouterr().out
