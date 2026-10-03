import pytest

from pe_builder import build_pe


@pytest.fixture
def pe_builder():
    return build_pe
