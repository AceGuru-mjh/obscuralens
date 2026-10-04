"""Pattern-engine unit tests (offline; pure functions in advanced.patterns)."""

from datetime import datetime, timezone

from obscuralens.advanced import patterns

UTC = timezone.utc


def _dt(hour: int, minute: int = 0, day: int = 1) -> datetime:
    return datetime(2026, 1, day, hour, minute, tzinfo=UTC)


def test_is_night_window():
    assert patterns._is_night(_dt(23)) is True   # 23:00 -> night
    assert patterns._is_night(_dt(2)) is True    # 02:00 -> night
    assert patterns._is_night(_dt(5, 59)) is True
    assert patterns._is_night(_dt(6)) is False   # 06:00 -> day
    assert patterns._is_night(_dt(12)) is False
    assert patterns._is_night(_dt(21, 59)) is False
    assert patterns._is_night(_dt(22)) is True   # 22:00 -> night


def test_cadence_single_lookup_has_null_stats():
    out = patterns._cadence([_dt(9)])
    assert out['lookups'] == 1
    assert out['span_days'] is None
    assert out['mean_interval_hours'] is None
    assert out['median_interval_hours'] is None
    assert out['first_seen'] == out['last_seen']


def test_cadence_multiple_lookups():
    moments = [_dt(9), _dt(9, 30), _dt(11)]
    out = patterns._cadence(moments)
    assert out['lookups'] == 3
    # Span 2h = 0.08 days (rounded to 2 dp).
    assert out['span_days'] == 0.08
    assert out['mean_interval_hours'] == 1.0     # (0.5 + 1.5) / 2
    assert out['median_interval_hours'] == 1.0
    assert out['min_interval_minutes'] == 30.0   # 0.5h * 60
    assert out['max_interval_days'] == round(1.5 / 24.0, 2)


def test_bursts_groups_within_30_min_window():
    # Three lookups inside 30 minutes form one burst.
    moments = [
        _dt(8), _dt(8, 10), _dt(8, 20),
        _dt(10),               # > 30 min after opener -> new run (too short)
        _dt(12), _dt(12, 5), _dt(12, 10), _dt(12, 15),  # 4 -> burst
    ]
    bursts = patterns._bursts(moments)
    assert len(bursts) == 2
    first, second = bursts
    assert first['count'] == 3
    assert second['count'] == 4
    assert first['start'] and second['start']  # both stamped with openers


def test_bursts_ignore_short_runs():
    moments = [_dt(8), _dt(8, 10), _dt(10)]  # only a 2-lookup run
    assert patterns._bursts(moments) == []


def test_peak_window_picks_busiest_cell_and_tiebreak():
    matrix = [[0] * 24 for _ in range(7)]
    matrix[1][10] = 5   # Tuesday 10:00
    matrix[3][8] = 5    # Thursday 08:00 (tie -> earlier weekday wins)
    matrix[0][0] = 3
    peak = patterns._peak_window(matrix)
    assert peak['weekday'] == 1 and peak['hour'] == 10 and peak['count'] == 5


def test_peak_window_empty_matrix():
    matrix = [[0] * 24 for _ in range(7)]
    peak = patterns._peak_window(matrix)
    # First cell wins ties (0 > -1), so hour/weekday are 0, not None.
    assert peak['count'] == 0
    assert peak['hour'] == 0 and peak['weekday'] == 0
