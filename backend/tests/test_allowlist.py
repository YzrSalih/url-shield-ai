from app.allowlist import load_known_domains, match_known_domain

KNOWN = {"paypal.com", "github.com", "bbc.co.uk"}


def test_known_domain_and_www_match():
    assert match_known_domain("https://www.paypal.com/signin", KNOWN) == "paypal.com"
    assert match_known_domain("http://github.com/login", KNOWN) == "github.com"
    assert match_known_domain("https://www.bbc.co.uk/news", KNOWN) == "bbc.co.uk"


def test_subdomains_and_lookalikes_do_not_match():
    # Content on subdomains is not trusted, and look-alike domains are different domains
    assert match_known_domain("http://login.paypal.com.account-verify.tk/", KNOWN) is None
    assert match_known_domain("http://evil.github.com/", KNOWN) is None
    assert match_known_domain("http://paypal-secure-login.com/", KNOWN) is None


def test_shorteners_and_free_hosting_are_never_trusted(tmp_path):
    f = tmp_path / "tranco.csv"
    f.write_text("1,google.com\n2,bit.ly\n3,000webhostapp.com\n4,github.io\n5,example.org\n")
    known = load_known_domains(str(f), top=4)
    assert known == {"google.com"}          # rank 5 is beyond the top-4 limit
    assert match_known_domain("https://bit.ly/3xYz9Ab", known | {"bit.ly"}) is None


def test_user_content_platforms_are_never_trusted():
    known = {"pastebin.com", "angelfire.com", "github.com"}
    assert match_known_domain("https://pastebin.com/raw/tMLRC8ww", known) is None
    assert match_known_domain("http://www.angelfire.com/il/page/", known) is None
