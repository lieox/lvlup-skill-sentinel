from sentinel.common import Candidate
from sentinel.score import score_candidate, band_label


def test_official_owner_scores_high():
    c = Candidate(name="skills", publisher="anthropics", stars=1000,
                  last_updated="2026-06-01", license="MIT")
    score_candidate(c)
    assert c.score >= 70


def test_anonymous_new_scores_low():
    c = Candidate(name="x", publisher="", stars=0, last_updated="", license="")
    score_candidate(c)
    assert c.score < 40


def test_requires_code_execution_penalized():
    base = Candidate(name="a", publisher="someone", stars=10, last_updated="2026-06-01")
    needs = Candidate(name="a", publisher="someone", stars=10, last_updated="2026-06-01",
                      requires_code_execution=True)
    score_candidate(base)
    score_candidate(needs)
    assert needs.score < base.score


def test_band_label_thresholds():
    assert band_label(90) == "excellent"
    assert band_label(65) == "good"
    assert band_label(45) == "moderate"
    assert band_label(10) == "weak/unknown"
