from sentinel.evaluation import evaluate, load_cases


def test_security_gate():
    r = evaluate(load_cases("examples/security_cases.json"))
    assert r.cases == 10
    assert r.failed == 0
    assert r.pass_rate == 1.0
    assert r.false_positive_rate == 0.0
    assert r.gate_passed
