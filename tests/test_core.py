"""Unit tests for core helpers (no network)."""
from pathlib import Path

from vrt_scanner.core import (
    set_query_param, query_params, same_origin, Scope, VRTCatalog,
)
from vrt_scanner.modules import _similar

CATALOG = Path(__file__).resolve().parent.parent / "vrt_catalog"


def test_set_query_param_replaces_only_target():
    u = "http://h/p?a=1&b=2"
    assert set_query_param(u, "a", "X") == "http://h/p?a=X&b=2"


def test_query_params_lists_keys():
    assert query_params("http://h/p?a=1&b=2&a=3") == ["a", "b", "a"]
    assert query_params("http://h/p") == []


def test_same_origin():
    assert same_origin("http://h/a", "http://h/b")
    assert not same_origin("http://h/a", "https://h/a")   # scheme differs
    assert not same_origin("http://h/a", "http://other/a")


def test_scope_allows_host_and_subdomain_only():
    s = Scope(["example.com"])
    assert s.allows("http://example.com/x")
    assert s.allows("http://sub.example.com/x")
    assert not s.allows("http://evil.com/x")
    assert not s.allows("http://notexample.com/x")
    assert not s.allows("not-a-url")


def test_similar_soft404_heuristic():
    assert _similar("abc", "abc")
    assert _similar("a" * 1000, "a" * 1010)       # within 5% length
    assert not _similar("a" * 1000, "a" * 2000)   # clearly different


def test_catalog_loads_known_leaf():
    cat = VRTCatalog.load_dir(CATALOG)
    info = cat.info("server_side_injection.sql_injection")
    assert info is not None
    assert 1 <= info["priority"] <= 5
    assert cat.info("this.leaf.does.not.exist") is None
    cfg = cat.leaf_config("server_side_injection.sql_injection")
    assert cfg["enabled"] is True
