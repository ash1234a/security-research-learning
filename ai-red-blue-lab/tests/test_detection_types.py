import builtins
import importlib
import sys

import pytest


def test_rule_match_is_shared_across_import_paths():
    from detection import RuleMatch as from_package
    from detection.types import RuleMatch as from_types
    from detection.yara_x_engine import RuleMatch as from_engine

    assert from_package is from_types is from_engine


def test_analyzer_core_imports_without_yara_x(monkeypatch):
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "yara_x" or name.startswith("yara_x."):
            raise ModuleNotFoundError("yara_x blocked for test")
        return real_import(name, *args, **kwargs)

    saved = {
        key: mod
        for key, mod in sys.modules.items()
        if key == "yara_x" or key == "detection" or key.startswith("detection.") or key == "analyzer.core"
    }
    for key in saved:
        monkeypatch.delitem(sys.modules, key)
    monkeypatch.setattr(builtins, "__import__", blocked)
    try:
        core = importlib.import_module("analyzer.core")
        report = core.analyze_bytes(b"not a pe file")
        assert report["detections"] is None

        import detection

        with pytest.raises(ModuleNotFoundError):
            detection.YaraXEngine
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
        for key in [k for k in sys.modules if k == "detection" or k.startswith("detection.") or k == "analyzer.core"]:
            del sys.modules[key]
        sys.modules.update(saved)
