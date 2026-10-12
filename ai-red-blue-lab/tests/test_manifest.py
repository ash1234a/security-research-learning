import pytest

from evaluation.manifest import ManifestError, load_manifest, parse_manifest

A = "a" * 64
B = "b" * 64
HEADER = "sha256,label,family,source\n"


def test_parses_four_field_manifest(tmp_path) -> None:
    path = tmp_path / "m.csv"
    path.write_text(HEADER + f"{A.upper()},malicious,Fam,synthetic\n{B},benign,,pip-benign\n\n")
    entries = load_manifest(path)
    assert [e.sha256 for e in entries] == [A, B]  # 소문자로 정규화, 빈 줄 무시
    assert entries[0].label == "malicious" and entries[0].family == "Fam"
    assert entries[1].family == "" and not entries[1].is_smoke


def test_smoke_sources_are_flagged() -> None:
    entries = parse_manifest(HEADER + f"{A},malicious,EICAR,eicar\n{B},malicious,,amtso\n")
    assert all(e.is_smoke for e in entries)


@pytest.mark.parametrize(
    "body, message",
    [
        ("", "빈 매니페스트"),
        ("sha256,label,source\n", "헤더"),
        ("sha256,label,family,source,extra\n", "헤더"),
        (HEADER + f"{A},malicious,x\n", "열이 4개"),
        (HEADER + "abc,malicious,,synthetic\n", "sha256 형식"),
        (HEADER + f"{A},evil,,synthetic\n", "label"),
        (HEADER + f"{A},benign,,theZoo\n", "알 수 없는 source"),
        (HEADER + f"{A},benign,,synthetic\n{A},benign,,synthetic\n", "3행: 중복"),
    ],
)
def test_rejects_invalid_manifest(body: str, message: str) -> None:
    with pytest.raises(ManifestError, match=message):
        parse_manifest(body)
