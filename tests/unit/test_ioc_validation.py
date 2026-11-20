import pytest

from siren_threatwatch.iocs.validation import (
    IocType,
    IocValidationError,
    defang,
    detect_type,
    refang,
    validate_indicator,
)


@pytest.mark.parametrize(
    ("raw", "expected_type", "canonical"),
    [
        ("198.51.100.7", IocType.IPV4, "198.51.100.7"),
        ("198[.]51[.]100[.]7", IocType.IPV4, "198.51.100.7"),
        ("2001:DB8:0:0::1", IocType.IPV6, "2001:db8::1"),
        ("Example.COM.", IocType.DOMAIN, "example.com"),
        ("evil[.]example[dot]org", IocType.DOMAIN, "evil.example.org"),
        ("bücher.example", IocType.DOMAIN, "xn--bcher-kva.example"),
        ("hxxp://Evil.Example[.]com/a?b=1#frag", IocType.URL, "http://evil.example.com/a?b=1"),
        ("https://example.com", IocType.URL, "https://example.com/"),
        ("hxxps[://]bad.example.net/x", IocType.URL, "https://bad.example.net/x"),
        ("d41d8cd98f00b204e9800998ecf8427e", IocType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        (
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
            IocType.SHA1,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            IocType.SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ],
)
def test_validate_and_canonicalise(raw, expected_type, canonical):
    result = validate_indicator(raw)
    assert result.ioc_type == expected_type
    assert result.value == canonical
    assert result.original == raw  # original evidence preserved verbatim


def test_sha512_detected():
    assert detect_type("a" * 128) == IocType.SHA512


@pytest.mark.parametrize(
    ("raw", "ioc_type"),
    [
        ("", None),
        ("   ", None),
        ("999.1.1.1", "ipv4"),
        ("not a domain", None),
        ("localhost", "domain"),
        ("-bad-.example.com", "domain"),
        ("example.c0m", "domain"),
        ("javascript:alert(1)", "url"),
        ("http:///nohost", "url"),
        ("abc123", "sha256"),
        ("z" * 64, "sha256"),
        ("2001:db8::1", "ipv4"),
        ("x" * 3000, None),
        ("evil.com\n", None),
        ("example.com", "bogus-type"),
    ],
)
def test_invalid_indicators_rejected(raw, ioc_type):
    with pytest.raises(IocValidationError):
        validate_indicator(raw, ioc_type)


def test_routability_flag():
    assert validate_indicator("10.0.0.1").is_routable is False
    assert validate_indicator("192.0.2.1").is_routable is False  # documentation range
    assert validate_indicator("8.8.8.8").is_routable is True


def test_explicit_type_must_match():
    assert validate_indicator("example.com", "domain").ioc_type == IocType.DOMAIN
    with pytest.raises(IocValidationError):
        validate_indicator("example.com", "ipv4")


def test_defang_round_trip():
    url = "http://evil.example.com/path.php"
    shown = defang(url, IocType.URL)
    assert "http://" not in shown and "evil.example.com" not in shown
    assert shown == "hxxp[://]evil[.]example[.]com/path.php"
    assert refang(shown) == url
    assert defang("evil.example.com", "domain") == "evil[.]example[.]com"
    assert defang("1.2.3.4", "ipv4") == "1[.]2[.]3[.]4"
    assert defang("a" * 64, "sha256") == "a" * 64


def test_entity_key_dedup_equivalence():
    a = validate_indicator("hxxp://EVIL[.]example.com")
    b = validate_indicator("http://evil.example.com/")
    assert a.entity_key == b.entity_key
