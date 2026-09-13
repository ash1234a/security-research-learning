from analyzer.entropy import shannon_entropy


def test_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_entropy_repeated_byte_is_zero():
    assert shannon_entropy(b"A" * 128) == 0.0


def test_entropy_two_symbols_is_one_bit():
    value = shannon_entropy(b"AB" * 128)
    assert abs(value - 1.0) < 1e-9
