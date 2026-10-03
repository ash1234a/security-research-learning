from analyzer.strings import extract_ascii_strings, extract_utf16le_strings


def test_extract_ascii_strings():
    data = b"\x00abc\x00HELLO-WORLD\x00xyz"
    assert extract_ascii_strings(data) == ["HELLO-WORLD"]


def test_extract_utf16le_strings():
    text = "MALWARE_TEST".encode("utf-16le")
    values = extract_utf16le_strings(b"\x00\x01" + text + b"\x02")
    assert "MALWARE_TEST" in values


def test_string_limit_is_respected():
    data = b"\x00".join(f"STRING{i:03d}".encode() for i in range(50))

    assert len(extract_ascii_strings(data, limit=10)) == 10
    assert extract_ascii_strings(data, limit=0) == []
