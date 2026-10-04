"""Batch renderer tests (offline; pure functions in advanced.batch).

Covers the CSV/JSON/Markdown serialisation layer, field ranking and the
defensive flattening of arbitrary tracker payloads.
"""

import json

from obscuralens.advanced import batch

# A run_batch-style payload: per-target entries with merged info.
RUN = {
    'kind': 'ip',
    'results': [
        {
            'target': '8.8.8.8',
            'success': True,
            'field_count': 3,
            'result': {'info': {
                'country_name': 'United States',
                'asn': 15169,
                'tags': ['dns', 'public'],
            }},
        },
        {
            'target': '1.1.1.1',
            'success': True,
            'field_count': 2,
            'result': {'info': {
                'country_name': 'Australia',
                'asn': 13335,
            }},
        },
        {
            'target': 'invalid',
            'success': False,
            'field_count': 0,
            'error': 'bad address',
            'result': None,
        },
    ],
}


def test_result_rows_accepts_run_and_raw_list():
    assert len(batch._result_rows(RUN)) == 3
    assert len(batch._result_rows(RUN['results'])) == 3
    assert batch._result_rows({'results': 'nope'}) == []
    assert batch._result_rows('junk') == []


def test_stringify_flattens_common_shapes():
    assert batch._stringify(None) == ''
    assert batch._stringify(True) == 'true'
    assert batch._stringify(False) == 'false'
    assert batch._stringify([1, 'a', None]) == '1; a'
    assert batch._stringify({'a': 1}) == json.dumps({'a': 1})
    assert batch._stringify(42) == '42'


def test_top_fields_ranks_by_frequency_then_name():
    rows = batch._result_rows(RUN)
    fields = batch._top_fields(rows, limit=3)
    # asn and country_name both appear in 2 rows; tags in 1.
    # Tie-break is name ascending, so asn precedes country_name.
    assert fields == ['asn', 'country_name', 'tags']


def test_to_csv_headers_and_rows():
    csv_text = batch.to_csv(RUN)
    lines = csv_text.strip().split('\n')
    header = lines[0].split(',')
    assert header[:4] == ['target', 'success', 'field_count', 'error']
    assert 'country_name' in header
    # The failed row keeps its place with empty cells for missing fields.
    failed = [line for line in lines[1:] if line.startswith('invalid,')][0]
    assert failed.startswith('invalid,false,0,bad address')
    assert failed.endswith(',,,')


def test_to_json_preserves_full_result():
    parsed = json.loads(batch.to_json(RUN))
    assert parsed == RUN


def test_to_markdown_escapes_pipes_and_caps_cells():
    md = batch.to_markdown({
        'results': [{
            'target': 'x',
            'success': False,
            'field_count': 0,
            'error': 'pipe|broken',
        }],
    })
    assert 'pipe\\|broken' in md
    # The table only carries target/status/fields/error; no info fields.
    assert '| x | failed | 0 | pipe\\|broken |' in md


def test_save_writes_markdown_and_json(tmp_path):
    md_path = tmp_path / 'out.md'
    json_path = tmp_path / 'out.json'
    batch.save(str(md_path), RUN, fmt='markdown')
    batch.save(str(json_path), RUN, fmt='json')
    assert md_path.read_text(encoding='utf-8').strip()
    parsed = json.loads(json_path.read_text(encoding='utf-8'))
    assert parsed == RUN
