import pytest

from app.utils.extractor import FEATURE_NAMES, extract_features, normalize_url


def feats(url):
    return dict(zip(FEATURE_NAMES, extract_features(url)))


def test_feature_count_matches_names():
    assert len(extract_features("https://www.google.com")) == len(FEATURE_NAMES)


def test_scheme_and_www_do_not_change_features():
    # Prevents the model from learning dataset formatting (data leakage)
    a = extract_features("https://www.example.com/login")
    b = extract_features("example.com/login")
    c = extract_features("http://example.com/login")
    assert a == b == c


def test_ip_host_detected():
    assert feats("http://192.168.1.1/login.php")["has_ip_host"] == 1


def test_ip_like_path_not_flagged():
    assert feats("https://example.com/v/1.2.3.4/file")["has_ip_host"] == 0


def test_suspicious_signals():
    f = feats("http://paypal.com.account-verify.tk/webscr?cmd=login")
    assert f["suspicious_tld"] == 1
    assert f["suspicious_keyword_count"] >= 3
    assert f["subdomain_count"] >= 2


def test_shortener_and_punycode():
    assert feats("https://bit.ly/abc123")["is_shortener"] == 1
    assert feats("http://xn--pple-43d.com")["has_punycode"] == 1


def test_malformed_url_does_not_crash():
    assert len(extract_features("http://[::1:bad")) == len(FEATURE_NAMES)


def test_normalize_adds_scheme():
    assert normalize_url("  example.com/login ") == "http://example.com/login"


@pytest.mark.parametrize("bad", ["", "   ", "http://"])
def test_normalize_rejects_invalid(bad):
    with pytest.raises(ValueError):
        normalize_url(bad)


def test_brand_impersonation():
    assert feats("http://paypal.com.account-verify.tk/login")["brand_in_subdomain"] == 1
    assert feats("https://www.paypal.com/signin")["brand_in_subdomain"] == 0
    assert feats("paypal-secure-login.com")["brand_in_subdomain"] == 1


def test_brand_no_false_substring_hits():
    assert feats("groups.example.com/purchase")["brand_in_path"] == 0
    assert feats("news.com/pineapple-recipes")["brand_in_path"] == 0


def test_free_hosting():
    assert feats("carol.000webhostapp.com/apple/id")["free_hosting"] == 1


def test_url_anatomy_parts():
    from app.anatomy import url_anatomy
    parts = {p["part"]: p for p in url_anatomy("http://paypal.com.account-verify.tk/webscr?cmd=login")}
    assert parts["subdomain"]["level"] == "flag"
    assert parts["tld"]["level"] == "flag"
    assert parts["domain"]["text"] == "account-verify"
    real = {p["part"]: p for p in url_anatomy("https://www.paypal.com/signin")}
    assert real["domain"]["level"] == "ok"
    ip = {p["part"]: p for p in url_anatomy("http://45.13.22.8/bins/mozi.arm7")}
    assert ip["host"]["level"] == "flag" and ip["path"]["level"] == "flag"
