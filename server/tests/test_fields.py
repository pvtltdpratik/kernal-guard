from __future__ import annotations

import pytest

from app.collectors.fields import clean, parse_hashes, to_bool, to_int


@pytest.mark.parametrize(
    ("value", "expected"),
    [("7432", 7432), ("0x1d08", 7432), (" 12 ", 12), ("0xZZ", None), ("abc", None), (None, None)],
)
def test_to_int(value: str | None, expected: int | None) -> None:
    assert to_int(value) == expected


@pytest.mark.parametrize(("value", "expected"), [("true", True), ("False", False), ("yes", None), (None, None)])
def test_to_bool(value: str | None, expected: bool | None) -> None:
    assert to_bool(value) == expected


def test_parse_hashes_keeps_only_valid_digests() -> None:
    parsed = parse_hashes(
        "SHA1=8C2D0A4A3F1E9B7C6D5E4F3A2B1C0D9E8F7A6B5C,MD5=short,SHA256=" + "G" * 64 + ",IMPHASH=" + "a" * 32
    )
    assert parsed == {"SHA1": "8c2d0a4a3f1e9b7c6d5e4f3a2b1c0d9e8f7a6b5c", "IMPHASH": "a" * 32}


def test_parse_hashes_empty() -> None:
    assert parse_hashes(None) == {}
    assert parse_hashes("") == {}


@pytest.mark.parametrize(("value", "expected"), [("-", None), ("  ", None), (None, None), (" x ", "x")])
def test_clean(value: str | None, expected: str | None) -> None:
    assert clean(value) == expected
