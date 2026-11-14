"""Every scenario causes its hazard unprotected; each expected mitigation prevents or detects it.

The runs are done in two worker processes to keep the suite fast.
"""

from concurrent.futures import ProcessPoolExecutor

import pytest

from icssim.runner import _cell
from icssim.scenarios import SCENARIOS


@pytest.fixture(scope="module")
def cells():
    jobs = [(k, "none", 1) for k in SCENARIOS]
    jobs += [(k, m, 1) for k, cls in SCENARIOS.items() for m in cls.expected]
    with ProcessPoolExecutor(max_workers=2) as ex:
        return {(k, c): cell for k, c, cell, _ in ex.map(_cell, jobs)}


@pytest.mark.parametrize("key", list(SCENARIOS))
def test_unprotected_run_causes_target_hazard(cells, key):
    cell = cells[(key, "none")]
    assert cell["outcome"] == "hazard", cell
    assert set(SCENARIOS[key].target_hazards) & set(cell["hazards"])


@pytest.mark.parametrize("key,mit", [(k, m) for k, cls in SCENARIOS.items() for m in cls.expected])
def test_expected_mitigation_outcome(cells, key, mit):
    cell = cells[(key, mit)]
    assert cell["outcome"] == SCENARIOS[key].expected[mit], cell
    assert cell["ttd_s"] is not None or mit == "sis" and cell["outcome"] == "prevented"
