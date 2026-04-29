from risk_rules import label_risk, score_transaction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tx(**overrides):
    """Return a zero-risk baseline transaction with any fields overridden."""
    base = {
        "device_risk_score": 10,
        "is_international": 0,
        "amount_usd": 100,
        "velocity_24h": 1,
        "failed_logins_24h": 0,
        "prior_chargebacks": 0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# label_risk — boundary conditions
# ---------------------------------------------------------------------------

def test_label_risk_low_boundary():
    assert label_risk(0) == "low"
    assert label_risk(29) == "low"


def test_label_risk_medium_boundary():
    assert label_risk(30) == "medium"
    assert label_risk(59) == "medium"


def test_label_risk_high_boundary():
    assert label_risk(60) == "high"
    assert label_risk(100) == "high"


def test_label_risk_thresholds():
    assert label_risk(10) == "low"
    assert label_risk(35) == "medium"
    assert label_risk(75) == "high"


# ---------------------------------------------------------------------------
# score_transaction — device risk
# ---------------------------------------------------------------------------

def test_device_risk_below_40_adds_nothing():
    assert score_transaction(_tx(device_risk_score=39)) == 0


def test_device_risk_mid_tier_adds_10():
    assert score_transaction(_tx(device_risk_score=40)) == 10
    assert score_transaction(_tx(device_risk_score=69)) == 10


def test_device_risk_high_adds_25():
    assert score_transaction(_tx(device_risk_score=70)) == 25
    assert score_transaction(_tx(device_risk_score=90)) == 25


# ---------------------------------------------------------------------------
# score_transaction — international flag
# ---------------------------------------------------------------------------

def test_domestic_adds_nothing():
    assert score_transaction(_tx(is_international=0)) == 0


def test_international_adds_15():
    assert score_transaction(_tx(is_international=1)) == 15


# ---------------------------------------------------------------------------
# score_transaction — transaction amount
# ---------------------------------------------------------------------------

def test_amount_below_500_adds_nothing():
    assert score_transaction(_tx(amount_usd=499)) == 0


def test_amount_500_to_999_adds_10():
    assert score_transaction(_tx(amount_usd=500)) == 10
    assert score_transaction(_tx(amount_usd=999)) == 10


def test_amount_1000_plus_adds_25():
    assert score_transaction(_tx(amount_usd=1000)) == 25
    assert score_transaction(_tx(amount_usd=1200)) == 25


def test_large_amount_adds_risk():
    tx = {
        "device_risk_score": 10,
        "is_international": 0,
        "amount_usd": 1200,
        "velocity_24h": 1,
        "failed_logins_24h": 0,
        "prior_chargebacks": 0,
    }
    assert score_transaction(tx) >= 25


# ---------------------------------------------------------------------------
# score_transaction — transaction velocity
# ---------------------------------------------------------------------------

def test_velocity_below_3_adds_nothing():
    assert score_transaction(_tx(velocity_24h=2)) == 0


def test_velocity_3_to_5_adds_5():
    assert score_transaction(_tx(velocity_24h=3)) == 5
    assert score_transaction(_tx(velocity_24h=5)) == 5


def test_velocity_6_plus_adds_20():
    assert score_transaction(_tx(velocity_24h=6)) == 20
    assert score_transaction(_tx(velocity_24h=10)) == 20


# ---------------------------------------------------------------------------
# score_transaction — failed logins
# ---------------------------------------------------------------------------

def test_failed_logins_below_2_adds_nothing():
    assert score_transaction(_tx(failed_logins_24h=1)) == 0


def test_failed_logins_2_to_4_adds_10():
    assert score_transaction(_tx(failed_logins_24h=2)) == 10
    assert score_transaction(_tx(failed_logins_24h=4)) == 10


def test_failed_logins_5_plus_adds_20():
    assert score_transaction(_tx(failed_logins_24h=5)) == 20
    assert score_transaction(_tx(failed_logins_24h=9)) == 20


# ---------------------------------------------------------------------------
# score_transaction — prior chargebacks
# ---------------------------------------------------------------------------

def test_no_prior_chargebacks_adds_nothing():
    assert score_transaction(_tx(prior_chargebacks=0)) == 0


def test_one_prior_chargeback_adds_5():
    assert score_transaction(_tx(prior_chargebacks=1)) == 5


def test_two_plus_prior_chargebacks_adds_20():
    assert score_transaction(_tx(prior_chargebacks=2)) == 20
    assert score_transaction(_tx(prior_chargebacks=3)) == 20


# ---------------------------------------------------------------------------
# score_transaction — score clamping
# ---------------------------------------------------------------------------

def test_score_floor_is_zero():
    assert score_transaction(_tx()) == 0


def test_score_ceiling_is_100():
    # All high-risk signals combined exceed 100 before clamping
    assert score_transaction(_tx(
        device_risk_score=85,
        is_international=1,
        amount_usd=1500,
        velocity_24h=8,
        failed_logins_24h=6,
        prior_chargebacks=3,
    )) == 100


# ---------------------------------------------------------------------------
# Regression tests — known fraud patterns from real data
#
# These pin the expected score for two confirmed-fraud transactions so that
# any future sign inversion in the scoring rules fails immediately.
# ---------------------------------------------------------------------------

def test_high_device_risk_international_velocity_scores_high():
    # Mirrors tx 50003: device 81, international, $1250, velocity 6, 5 failed logins
    tx = _tx(
        device_risk_score=81,
        is_international=1,
        amount_usd=1250,
        velocity_24h=6,
        failed_logins_24h=5,
    )
    assert score_transaction(tx) == 100
    assert label_risk(score_transaction(tx)) == "high"


def test_repeat_fraudster_international_high_velocity_scores_high():
    # Mirrors tx 50006: device 77, international, velocity 7, 6 failed logins, 3 prior chargebacks
    tx = _tx(
        device_risk_score=77,
        is_international=1,
        amount_usd=399,
        velocity_24h=7,
        failed_logins_24h=6,
        prior_chargebacks=3,
    )
    assert score_transaction(tx) == 100
    assert label_risk(score_transaction(tx)) == "high"
