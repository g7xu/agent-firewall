from demo.eval import run_eval


def test_firewall_stops_every_attack_except_the_known_gap():
    results = run_eval()
    off, on = results["off"], results["on"]

    assert off["attacks_succeeded"] >= 15
    assert off["canary_cases_in_cloud"] > 0

    assert on["missed"] == ["A14"]
    assert on["canary_cases_in_cloud"] == 0
    assert on["false_alarms"] == 0
    assert on["expected_holds_seen"] == 1
