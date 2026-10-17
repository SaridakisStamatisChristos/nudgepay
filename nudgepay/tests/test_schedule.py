from app.scheduler import compute_stage
from datetime import date, timedelta

def test_stages():
    due = date(2025,1,10)
    assert compute_stage(due, due - timedelta(days=3)) == "T-3"
    assert compute_stage(due, due) == "DUE"
    assert compute_stage(due, due + timedelta(days=3)) == "+3"
    assert compute_stage(due, due + timedelta(days=7)) == "+7"
    assert compute_stage(due, due + timedelta(days=1)) is None
