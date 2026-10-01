"""Formatting and table rendering tests."""

from obscuralens.utils.formatting import (
    LABELS,
    fmt_value,
    label,
    rows_from_fields,
)
from obscuralens.utils.helpers import print_table, render_table


def test_label_lookup_and_fallback():
    assert label('rdap_abuse_email') == 'Abuse Email'
    assert label('some_new_field') == 'Some New Field'
    assert 'domain_age_days' in LABELS


def test_fmt_value_types():
    assert fmt_value('x', True) == 'yes'
    assert fmt_value('x', False) == 'no'
    assert fmt_value('ports', [80, 443]) == '80, 443'
    assert fmt_value('coordinates_by_source',
                     [{'source': 'a', 'lat': 1, 'lon': 2}]) == 'a(1,2)'
    assert '"a": 1' in fmt_value('x', {'a': 1})


def test_rows_from_fields_filters_and_labels():
    rows = rows_from_fields({'country': 'US', 'city': '', 'is_eu': False,
                             'ports': [80, 443], 'field_sources': {'x': ['a']}})
    labels = [row[0] for row in rows]
    assert 'Country' in labels
    assert 'City' not in labels          # empty is dropped
    assert 'Is EU' not in labels         # False is dropped in rows
    assert 'Field Sources' not in labels  # plumbing key skipped
    assert any(row[1] == '80, 443' for row in rows)


def test_render_table_variants():
    assert 'Country' in render_table([['Country', 'US']])
    assert 'US' in render_table([{'country': 'US'}])
    assert 'Value' in render_table({'a': 1})
    assert render_table([]) == ''


def test_print_table_accepts_row_lists(capsys):
    print_table([['Country', 'US'], ['City', 'NY']], headers=['Field', 'Value'])
    out = capsys.readouterr().out
    assert 'Country' in out and 'NY' in out
