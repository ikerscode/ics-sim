"""Carbonate chemistry used to turn alkalinity into pH.

Alkalinity mixes linearly between water bodies, pH does not. So the process
model tracks alkalinity (eq/L) and total inorganic carbon C_T (mol/L) and only
converts to pH when a sensor or the consequence model needs it.

Charge balance for a closed carbonate system:
    Alk = C_T * (a1 + 2 a2) + Kw/[H+] - [H+]
Constants are the usual 25 deg C values; temperature correction is ignored.
"""

import math

K1 = 10 ** -6.35
K2 = 10 ** -10.33
KW = 1e-14
LN10 = math.log(10)


def ph_from(alk: float, ct: float, guess: float = 7.5) -> float:
    """Solve the charge balance for pH with Newton's method (warm start from `guess`)."""
    ph = guess
    for _ in range(40):
        h = 10.0 ** -ph
        d = h * h + K1 * h + K1 * K2
        n = K1 * h + 2 * K1 * K2
        f = ct * n / d + KW / h - h - alk
        dfdh = ct * (K1 * d - n * (2 * h + K1)) / (d * d) - KW / (h * h) - 1.0
        step = f / (dfdh * -LN10 * h)
        step = max(-1.0, min(1.0, step))
        ph = max(0.0, min(14.5, ph - step))
        if abs(step) < 1e-6:
            break
    return ph


def alk_from(ph: float, ct: float) -> float:
    """Inverse of ph_from: alkalinity (eq/L) that gives `ph` for a given C_T."""
    h = 10.0 ** -ph
    d = h * h + K1 * h + K1 * K2
    return ct * (K1 * h + 2 * K1 * K2) / d + KW / h - h
