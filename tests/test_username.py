"""Username verdict logic and API platform tests."""

from obscuralens.trackers import username_sources as us
from obscuralens.trackers.username_tracker import UsernameResult, UsernameTracker


def test_platform_registry_includes_api_and_html():
    tracker = UsernameTracker()
    names = {p['name'] for p in tracker.platforms}
    assert {'GitHub', 'Keybase', 'HackerNews', 'Lichess', 'Codeberg',
            'DockerHub', 'Dev.to', 'Chess.com'} <= names
    api_count = sum(1 for p in tracker.platforms if p.get('api'))
    assert api_count == len(us.API_PLATFORMS)


def test_verdict_404_is_not_found(fake_response):
    tracker = UsernameTracker()
    status, confidence, reason = tracker._verdict(
        'GitHub', 'nobody', fake_response(status_code=404, text=''))
    assert status == 'not_found' and confidence == 'high'


def test_verdict_bot_wall_is_unknown(fake_response):
    tracker = UsernameTracker()
    status, _, _ = tracker._verdict(
        'Instagram', 'someone', fake_response(status_code=403, text='blocked'))
    assert status == 'unknown'


def test_verdict_not_found_marker(fake_response):
    tracker = UsernameTracker()
    status, confidence, _ = tracker._verdict(
        'Generic', 'someone',
        fake_response(status_code=200,
                      text='<html>User profile not found</html>'))
    assert status == 'not_found' and confidence == 'high'


def test_verdict_js_shell_is_unknown(fake_response):
    tracker = UsernameTracker()
    status, _, reason = tracker._verdict(
        'Generic', 'someone',
        fake_response(status_code=200, text='<html><title>App</title></html>'))
    assert status == 'unknown'
    assert 'no profile evidence' in reason


def test_verdict_github_evidence_is_found(fake_response):
    tracker = UsernameTracker()
    html = (
        '<html><head><meta property="og:title" content="octocat">'
        '<meta property="og:image" content="https://avatars/x.png">'
        '</head><body>Follow</body></html>'
    )
    status, confidence, _ = tracker._verdict(
        'GitHub', 'octocat', fake_response(status_code=200, text=html))
    assert status == 'found' and confidence in ('medium', 'high')


def test_keybase_verdict_and_profile():
    assert us._keybase_verdict({'status': {'code': 205}}) is False
    assert us._keybase_verdict(
        {'status': {'code': 0}, 'them': [{'basics': {'username': 'u'}}]}) is True
    assert us._keybase_verdict({'status': {'code': 1}}) is None

    profile = us._keybase_profile({'them': [{
        'basics': {'username_cased': 'Alice', 'ctime': 1500000000},
        'profile': {'bio': 'hi', 'location': 'Earth',
                    'website': 'https://alice.example'},
    }]})
    assert profile['name'] == 'Alice'
    assert profile['bio'] == 'hi'
    assert profile['links'] == ['https://alice.example']
    assert profile['created'].startswith('20')


def test_hn_verdict_handles_null():
    assert us._hn_verdict(None) is False
    assert us._hn_verdict({'id': 'pg'}) is True
    assert us._hn_verdict({'unexpected': 1}) is False


def test_api_profile_extractors():
    chess = us.api_profile('Chess.com', {
        'username': 'hikaru', 'name': 'Hikaru', 'followers': 10,
        'country': 'https://api.chess.com/pub/country/US',
        'joined': 1389043258, 'url': 'https://chess.com/member/hikaru',
    })
    assert chess['country'] == 'US'
    assert chess['followers'] == 10
    assert chess['joined'].startswith('20')

    hn = us.api_profile('HackerNews', {
        'id': 'pg', 'about': 'bug fixer', 'karma': 157316,
        'created': 1160418092, 'submitted': [1, 2, 3],
    })
    assert hn['karma'] == 157316
    assert hn['posts'] == 3

    lichess = us.api_profile('Lichess', {
        'id': 'github', 'username': 'github',
        'playTime': {'total': 7200},
        'perfs': {'bullet': {'rating': 1887}},
        'count': {'all': 5, 'win': 1},
    })
    assert lichess['name'] == 'github'
    assert lichess['play_time_hours'] == 2.0
    assert lichess['best_rating'] == 'bullet 1887'


def test_check_api_platform_404(fake_http):
    tracker = UsernameTracker()
    platform = next(p for p in tracker.platforms if p['name'] == 'Lichess')
    fake_http.json = lambda url, **kw: (False, None, 'not found')
    result = tracker._check_api_platform(platform, 'nobody', deep=True)
    assert result.status == 'not_found'
    assert result.confidence == 'high'


def test_check_api_platform_found_with_profile(fake_http):
    tracker = UsernameTracker()
    platform = next(p for p in tracker.platforms if p['name'] == 'Lichess')
    fake_http.json = lambda url, **kw: (True, {
        'id': 'alice', 'username': 'alice',
        'count': {'all': 10, 'win': 5},
        'profile': {'bio': 'hi'},
    }, '')
    result = tracker._check_api_platform(platform, 'alice', deep=True)
    assert result.status == 'found'
    assert result.profile['name'] == 'alice'
    assert result.profile['wins'] == 5


def test_track_filters_platforms(monkeypatch, tmp_env):
    tracker = UsernameTracker()
    checked = []

    def fake_check(platform, username, deep):
        checked.append(platform['name'])
        return UsernameResult(platform=platform['name'], url='u',
                              exists=True, status='found', confidence='high')

    monkeypatch.setattr(tracker, '_check_platform', fake_check)
    result = tracker.track('alice', platforms=['keybase', 'lichess'])
    assert result['found_count'] == 2
    assert sorted(checked) == ['Keybase', 'Lichess']


def test_track_records_failures(monkeypatch, tmp_env):
    tracker = UsernameTracker()

    def boom(platform, username, deep):
        raise RuntimeError('nope')

    monkeypatch.setattr(tracker, '_check_platform', boom)
    result = tracker.track('alice', platforms=['keybase'])
    assert result['unknown_count'] == 1
    assert result['errors']
