"""Shared password-candidate helpers, independent of Wi-Fi."""

import itertools

PRESETS = {
    "alpha": "abcdefghijklmnopqrstuvwxyz",
    "ALPHA": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digit": "0123456789",
    "alphanumeric": "abcdefghijklmnopqrstuvwxyz0123456789",
    "ALPHANUMERIC": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "special": "!@#$%^&*()_+|}>?",
    "all": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+|}>?",
}


def resolve_charset(raw):
    return PRESETS.get(raw, raw)


def generate(charset, min_len, max_len):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)
