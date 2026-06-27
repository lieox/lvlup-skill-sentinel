from sentinel.common import normalize_repo, relevance, days_since, Candidate


def test_normalize_repo_strips_git_and_lowercases():
    assert normalize_repo("https://github.com/Anthropics/Skills.git") == "anthropics/skills"


def test_normalize_repo_non_github_returns_empty():
    assert normalize_repo("https://example.com/x/y") == ""


def test_relevance_empty_query_is_one():
    c = Candidate(name="x", description="")
    assert relevance("", c) == 1.0


def test_relevance_counts_token_overlap():
    c = Candidate(name="pdf tools", description="merge split pdf")
    assert relevance("pdf merge", c) == 1.0


def test_days_since_handles_bad_input():
    assert days_since("not-a-date") is None


def test_days_since_valid_date_returns_positive():
    assert days_since("2020-01-01") > 1000


def test_candidate_key_prefers_repo():
    c = Candidate(name="X", repo_url="https://github.com/o/r")
    assert c.key() == "o/r"
