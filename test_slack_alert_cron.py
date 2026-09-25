"""Offline self-check for slack_alert_cron: mocks HTTP, verifies referrer parsing, Slack payload
escaping and limits, note posting, state files, locking and the dry-run / replay modes.

Run: python test_slack_alert_cron.py
"""

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import slack_alert_cron as cron

API = 'https://api.teamtailor.com/v1'


def read(path):
    with open(path) as f:
        return json.load(f)


def resp(json_data=None, status=200, headers=None, text=''):
    r = Mock()
    r.status_code = status
    r.ok = status < 400
    r.headers = headers or {}
    r.text = text
    r.json.return_value = json_data if json_data is not None else {}
    r.raise_for_status = Mock(side_effect=None if status < 400 else Exception(f'HTTP {status}'))
    return r


class Base(unittest.TestCase):
    """Temp dir for every state file, a clean environment with one Teamtailor account, no sleeping."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        for name in ('STATE', 'NOTED', 'AI_NOTED', 'LOCK', 'REPORT'):
            self.enterContext(patch.object(cron, name, os.path.join(self.tmp, name.lower() + '.json')))
        env = {k: v for k, v in os.environ.items() if not k.startswith('TEAMTAILOR_')}
        env.update({'TEAMTAILOR_API_KEY_TEST': 'k', 'TEAMTAILOR_NOTE_USER_ID': 'u1', 'SLACK_WEBHOOK_URL': 'https://hooks.example/x'})
        self.enterContext(patch.dict(os.environ, env, clear=True))
        self.enterContext(patch.object(cron.time, 'sleep'))
        self.enterContext(patch.object(cron, 'load_env'))  # never read the real .env
        self.enterContext(patch.object(sys, 'stderr', io.StringIO()))
        cron._tt_sessions.clear()
        cron.FAILURES.clear()
        cron._note_users.clear()
        self.calls = []

    def fake_session_request(self, handler):
        """Route Session.request through handler(method, url, kw) and record calls."""
        def _request(_self, method, url, **kw):
            self.calls.append((method, url, kw))
            return handler(method, url, kw)
        return self.enterContext(patch.object(cron.requests.Session, 'request', _request))

    def stderr(self):
        return sys.stderr.getvalue()


class TestReferrerParsing(unittest.TestCase):
    def test_bare_ip(self):
        cases = {'89.167.50.51': '89.167.50.51', '127.0.0.1:8765': '127.0.0.1', 'http://127.0.0.1:8765/': '127.0.0.1',
                 'http://89.167.50.51:3000/apply': '89.167.50.51', '[::1]:8080': '::1', '::1': '::1', ' 1.2.3.4 ': '1.2.3.4',
                 'https://www.linkedin.com/jobs/': None, 'linkedin.com': None, 'LinkedIn': None, 'http://[::1': None,
                 None: None, '': None}
        for value, want in cases.items():
            self.assertEqual(cron.bare_ip(value), want, value)

    def test_ai_tool_matches_hostname_only(self):
        self.assertEqual(cron.ai_tool('jobright.ai', None), 'Jobright')
        self.assertEqual(cron.ai_tool('Simplify', None), 'Simplify')
        self.assertEqual(cron.ai_tool(None, 'https://app.jackandjill.ai/apply'), 'Jack & Jill')
        self.assertEqual(cron.ai_tool('https://chatgpt.com/', None), 'ChatGPT')
        self.assertIsNone(cron.ai_tool('https://www.linkedin.com/posts/how-to-simplify-your-cv', None))
        self.assertIsNone(cron.ai_tool('https://example.com/?utm=hirify', None))
        self.assertIsNone(cron.ai_tool(None, None))

    def test_parse_ts_naive_is_utc(self):
        self.assertEqual(cron.parse_ts('2026-09-24T15:52:04').tzinfo, timezone.utc)
        self.assertEqual(cron.parse_ts('2026-09-24T15:52:04.078+02:00').utcoffset(), timedelta(hours=2))


class TestFindings(unittest.TestCase):
    def test_whitelist_covers_internal_sources_only(self):
        self.assertTrue(cron.whitelisted({'source': 'slack', 'user': 'jirabot', 'email': 'Unknown'}))
        self.assertTrue(cron.whitelisted({'source': 'zoom', 'user': 'x', 'email': 'jirabot'}))
        self.assertFalse(cron.whitelisted({'source': 'teamtailor', 'user': 'jirabot', 'email': 'tt:global:1'}))
        self.assertFalse(cron.whitelisted({'source': 'slack', 'user': 'ann', 'email': 'ann@x'}))

    def test_finding_key_falls_back_to_name_for_unknown_email(self):
        a = {'email': 'ann@x', 'user': 'ann', 'ip': '1.1.1.1', 'vpn_operator': 'KASM_VDI', 'source': 'slack'}
        self.assertEqual(cron.finding_key(a), 'ann@x|1.1.1.1|KASM_VDI|slack')
        self.assertEqual(cron.finding_key(a), cron.legacy_key(a))
        g1 = {'email': 'Unknown', 'user': 'Guest One', 'ip': '1.1.1.1', 'vpn_operator': 'KASM_VDI', 'source': 'zoom'}
        g2 = dict(g1, user='Guest Two')
        self.assertNotEqual(cron.finding_key(g1), cron.finding_key(g2))
        self.assertEqual(cron.legacy_key(g1), 'Unknown|1.1.1.1|KASM_VDI|zoom')

    def test_new_findings_dedups_and_honours_legacy_keys(self):
        seen = {'a@x|1.1.1.1|KASM_VDI|slack', 'Unknown|2.2.2.2|KASM_VDI|zoom'}
        new = cron.new_findings([{'email': 'a@x', 'ip': '1.1.1.1', 'vpn_operator': 'KASM_VDI', 'source': 'slack'},
                                 {'email': 'b@x', 'ip': '1.1.1.1', 'vpn_operator': 'KASM_VDI', 'source': 'slack'},
                                 {'email': 'b@x', 'ip': '1.1.1.1', 'vpn_operator': 'KASM_VDI', 'source': 'slack'},
                                 {'email': 'Unknown', 'user': 'old guest', 'ip': '2.2.2.2', 'vpn_operator': 'KASM_VDI', 'source': 'zoom'},
                                 {'email': 'Unknown', 'user': 'g1', 'ip': '3.3.3.3', 'vpn_operator': 'KASM_VDI', 'source': 'zoom'},
                                 {'email': 'Unknown', 'user': 'g2', 'ip': '3.3.3.3', 'vpn_operator': 'KASM_VDI', 'source': 'zoom'}], seen)
        self.assertEqual([a.get('email') + '/' + a.get('user', '') for a in new], ['b@x/', 'Unknown/g1', 'Unknown/g2'])
        self.assertEqual(len(seen), 5)


class TestPayload(unittest.TestCase):
    def sections(self, payload):
        return [b['text']['text'] for b in payload['blocks'] if b['type'] == 'section']

    def test_external_text_is_escaped(self):
        new = [{'user': 'Kim <!channel> <https://evil.example|Click me>', 'email': 'tt:global:1', 'candidate_id': '1',
                'account': 'global', 'company': 'X@eu', 'ip': '1.2.3.4', 'vpn_operator': 'ASTRILL_VPN', 'source': 'teamtailor',
                'tt_note': 'profile flagged', 'candidate_email': 'a@b.c', 'tt_jobs': [('Dev & Ops', 'R<e>c')]},
               {'user': 'bob', 'email': 'bob@team.blue', 'ip': '5.6.7.8', 'vpn_operator': 'KASM_VDI', 'source': 'zoom',
                'meeting_topic': '<!here> standup'}]
        raw = json.dumps(cron.build_payload(new), ensure_ascii=False)
        self.assertNotIn('<!channel>', raw)
        self.assertNotIn('<!here>', raw)
        self.assertNotIn('<https://evil.example|', raw)
        self.assertIn('Dev &amp; Ops', raw)
        self.assertIn('R&lt;e&gt;c', raw)
        self.assertIn('<https://app.teamtailor.com/companies/X@eu/candidates/segment/all/candidate/1|Kim &lt;!channel&gt;', raw)

    def test_block_kit_limits(self):
        big = [{'user': f'user{i}', 'email': f'u{i}@x', 'ip': '1.1.1.1', 'vpn_operator': 'ASTRILL_VPN', 'source': 'slack'}
               for i in range(3000)]
        p = cron.build_payload(big)
        self.assertLessEqual(len(p['blocks']), cron.SLACK_MAX_BLOCKS)
        self.assertTrue(all(len(s) <= cron.SLACK_SECTION_MAX for s in self.sections(p)))
        self.assertIn('omitted', self.sections(p)[-1])
        self.assertLessEqual(len(p['text']), cron.SLACK_SECTION_MAX)
        self.assertEqual(p['blocks'][0]['type'], 'header')
        self.assertEqual(p['blocks'][-1]['type'], 'context')

    def test_overlong_candidate_is_clipped_and_jobs_capped(self):
        one = [{'user': 'x' * 5000, 'email': 'tt:global:2', 'candidate_id': '2', 'account': 'global', 'company': 'X@eu',
                'ip': '1.2.3.4', 'vpn_operator': 'ASTRILL_VPN', 'source': 'teamtailor', 'tt_note': 'profile flagged',
                'tt_jobs': [(f'Job {i}', 'R') for i in range(80)]}]
        secs = self.sections(cron.build_payload(one))
        self.assertEqual(len(secs), 1)
        self.assertLessEqual(len(secs[0]), cron.SLACK_SECTION_MAX)
        self.assertRegex(secs[0], r'<https://app\.teamtailor\.com/[^|>]+\|x+…>')  # link label clipped, link still balanced
        two = [dict(one[0], user='short')]
        s = self.sections(cron.build_payload(two))[0]
        self.assertEqual(s.count('↳'), cron.MAX_JOBS_SHOWN + 1)
        self.assertIn(f'and {80 - cron.MAX_JOBS_SHOWN} more application(s)', s)

    def test_singular_header_and_grouping(self):
        p = cron.build_payload([{'user': 'a', 'email': 'a@x', 'ip': '1.1.1.1', 'vpn_operator': 'KASM_VDI', 'source': 'other'}])
        self.assertEqual(p['blocks'][0]['text']['text'], '🚨 1 new VPN/proxy detection')
        self.assertIn('❓ *Other*', self.sections(p)[0])
        self.assertIn(f'Last {cron.WINDOW_HOURS}h window', p['blocks'][-1]['elements'][0]['text'])


class TestState(Base):
    def test_save_json_is_atomic_and_private(self):
        old = os.umask(0o022)
        try:
            cron.save_json(cron.STATE, ['b', 'a'])
        finally:
            os.umask(old)
        self.assertEqual(read(cron.STATE), ['b', 'a'])
        self.assertEqual(stat.S_IMODE(os.stat(cron.STATE).st_mode), 0o600)
        self.assertFalse(os.path.exists(cron.STATE + '.tmp'))
        self.assertEqual(cron.load_json(os.path.join(self.tmp, 'missing.json'), []), [])

    def test_corrupt_or_wrong_shaped_state_stops_the_run(self):
        for content in ('', '{"a": 1}', 'null', '"x"'):
            with open(cron.STATE, 'w') as f:
                f.write(content)
            with self.assertRaises(SystemExit) as cm:
                cron.load_json(cron.STATE, [])
            self.assertIn('repair or move it away', str(cm.exception))
        with open(cron.STATE, 'w') as f:
            f.write('["k"]')
        self.assertEqual(cron.load_json(cron.STATE, []), ['k'])

    def test_lock_excludes_a_second_process(self):
        fd = cron.acquire_lock()
        child = subprocess.run([sys.executable, '-c',
                                'import fcntl, os, sys\n'
                                f'fd = os.open({cron.LOCK!r}, os.O_RDWR | os.O_CREAT, 0o600)\n'
                                'try:\n    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); print("got")\n'
                                'except BlockingIOError:\n    print("blocked")'],
                               capture_output=True, text=True)
        self.assertEqual(child.stdout.strip(), 'blocked')
        cron.release_lock(fd)
        fd = cron.acquire_lock()  # free again
        cron.release_lock(fd)


class TestLoadEnv(unittest.TestCase):
    def test_real_environment_wins_and_export_prefix_is_tolerated(self):
        repo = tempfile.mkdtemp()
        with open(os.path.join(repo, '.env'), 'w') as f:
            f.write('# comment\nA_TEST_KEY="quoted"\nB_TEST_KEY=plain=with=equals\nexport C_TEST_KEY=exported\nbroken line\n')
        with patch.object(cron, 'REPO', repo), patch.dict(os.environ, {'A_TEST_KEY': 'real'}):
            for k in ('B_TEST_KEY', 'C_TEST_KEY'):
                os.environ.pop(k, None)
            cron.load_env()
            self.assertEqual(os.environ['A_TEST_KEY'], 'real')
            self.assertEqual(os.environ['B_TEST_KEY'], 'plain=with=equals')
            self.assertEqual(os.environ['C_TEST_KEY'], 'exported')
            self.assertNotIn('export C_TEST_KEY', os.environ)
        with patch.object(cron, 'REPO', os.path.join(repo, 'nowhere')):
            cron.load_env()  # missing .env is fine


class TestTeamtailorNotes(Base):
    def test_notes_saved_per_success_and_failures_retry_next_run(self):
        statuses = iter([200, 500])
        self.fake_session_request(lambda m, u, kw: resp(json_data={'data': []}) if m == 'GET' else resp(status=next(statuses)))
        new = [{'source': 'teamtailor', 'account': 'test', 'candidate_id': '1'},
               {'source': 'teamtailor', 'account': 'test', 'candidate_id': '2'},
               {'source': 'slack', 'email': 'x'}]
        cron.post_teamtailor_notes(new)
        self.assertEqual([a.get('tt_note') for a in new], ['profile flagged', 'note FAILED, flag manually', None])
        self.assertEqual(read(cron.NOTED), ['test:1'])
        posts = [c for c in self.calls if c[0] == 'POST']
        self.assertEqual(len(posts), 2)  # POSTs are not retried on 5xx
        self.assertTrue(all('/activities' in u and kw['params']['filter[code]'] == 'note' for m, u, kw in self.calls if m == 'GET'))
        body = posts[0][2]['json']['data']
        self.assertEqual(body['relationships']['candidate']['data']['id'], '1')
        self.assertEqual(body['relationships']['user']['data']['id'], 'u1')
        self.assertEqual(body['attributes']['note'], cron.TT_NOTE)
        self.assertIn('note failed for test:2', self.stderr())

        cron.post_teamtailor_notes([{'source': 'teamtailor', 'account': 'test', 'candidate_id': '1'}])
        self.assertEqual(len(posts), 2)  # already flagged: no request
        self.assertEqual(len(self.calls), 4)

    def test_note_already_on_profile_is_not_reposted(self):
        # e.g. posted before a state reset, or on a candidate since merged into this one; Teamtailor rewrites the HTML
        stored = cron.TT_NOTE.replace('(emil.stahl@team.blue)', '(<a href="mailto:emil.stahl@team.blue">emil.stahl@team.blue</a>)')
        acts = {'data': [{'attributes': {'code': 'note', 'data': json.dumps({'note': '<p>Great candidate</p>'})}},
                         {'attributes': {'code': 'note', 'data': json.dumps({'note': stored})}}]}
        self.fake_session_request(lambda m, u, kw: resp(json_data=acts) if m == 'GET' else resp())
        new = [{'source': 'teamtailor', 'account': 'test', 'candidate_id': '1'}]
        cron.post_teamtailor_notes(new)
        self.assertEqual(new[0]['tt_note'], 'already flagged')
        self.assertEqual(read(cron.NOTED), ['test:1'])
        self.assertEqual([m for m, u, kw in self.calls], ['GET'])
        # an AI info note with different text is still posted; the same one is not
        ai = [{'account': 'test', 'application_id': '10', 'candidate_id': '1', 'user': 'x', 'job': 'Dev', 'tool': 'the AI job tool Simplify'}]
        cron.post_ai_notes(ai)
        self.assertEqual([m for m, u, kw in self.calls], ['GET', 'GET', 'POST'])
        acts['data'].append({'attributes': {'code': 'note', 'data': json.dumps({'note': self.calls[-1][2]['json']['data']['attributes']['note']})}})
        cron._note_users.clear()
        for f in (cron.NOTED, cron.AI_NOTED):
            os.path.exists(f) and os.remove(f)  # state lost: the profile still says no
        cron.post_ai_notes(ai)
        self.assertEqual([m for m, u, kw in self.calls], ['GET', 'GET', 'POST', 'GET'])
        self.assertEqual(read(cron.AI_NOTED), ['test:10'])

    def test_notes_skip_without_key_and_in_dry_run(self):
        self.fake_session_request(lambda m, u, kw: resp())
        new = [{'source': 'teamtailor', 'account': 'nokey', 'candidate_id': '1'},
               {'source': 'teamtailor', 'account': 'test', 'candidate_id': '2'}]
        cron.post_teamtailor_notes(new, dry_run=True)
        self.assertEqual([a['tt_note'] for a in new], ['not flagged (no key/user configured)', 'dry run, not flagged'])
        self.assertEqual(self.calls, [])
        self.assertFalse(os.path.exists(cron.NOTED))

    def test_note_user_is_resolved_per_workspace(self):
        # plain TEAMTAILOR_NOTE_USER_ID: used as-is, no lookup
        self.fake_session_request(lambda m, u, kw: resp())
        self.assertEqual(cron.note_user_id('test'), 'u1')
        self.assertEqual(self.calls, [])
        # per-workspace override wins, still no lookup
        with patch.dict(os.environ, {'TEAMTAILOR_NOTE_USER_ID_TEST': 'u9', 'TEAMTAILOR_NOTE_USER_EMAIL': 'sec@example'}):
            self.assertEqual(cron.note_user_id('test'), 'u9')
        self.assertEqual(self.calls, [])
        # email configured: one GET per workspace per run, cached; nobody found -> None and one warning
        current = [[{'id': 'u2'}]]
        self.fake_session_request(lambda m, u, kw: resp(json_data={'data': current[0]}))
        self.calls.clear()
        with patch.dict(os.environ, {'TEAMTAILOR_NOTE_USER_EMAIL': 'sec@example', 'TEAMTAILOR_API_KEY_OTHER': 'k2'}):
            self.assertEqual(cron.note_user_id('test'), 'u2')
            self.assertEqual(cron.note_user_id('test'), 'u2')
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0][2]['params'], {'filter[email]': 'sec@example', 'page[size]': 1})
            current[0] = []
            self.assertIsNone(cron.note_user_id('other'))
            self.assertIsNone(cron.note_user_id('other'))
            self.assertEqual(len(self.calls), 2)
            self.assertIn('no Teamtailor user sec@example in workspace other', self.stderr())
            # ... unless add_teamtailor_emails found the job's recruiter: the note is posted as them
            new = [{'source': 'teamtailor', 'account': 'other', 'candidate_id': '6', 'tt_recruiter_id': 'rec1'}]
            cron.post_teamtailor_notes(new)
            self.assertEqual(new[0]['tt_note'], 'profile flagged')
            self.assertEqual(self.calls[-1][2]['json']['data']['relationships']['user']['data']['id'], 'rec1')
            # AI notes look the recruiter up per application
            self.fake_session_request(lambda m, u, kw: resp(json_data={'included': [{'type': 'jobs', 'id': 'j'}, {'type': 'users', 'id': 'rec2'}]}))
            self.calls.clear()
            cron.post_ai_notes([{'account': 'other', 'application_id': '70', 'candidate_id': '6', 'user': 'x', 'job': 'Dev', 'tool': 't'}])
            self.assertEqual([m for m, u, kw in self.calls], ['GET', 'GET', 'POST'])  # recruiter, existing notes, post
            self.assertIn('/job-applications/70', self.calls[0][1])
            self.assertEqual(self.calls[2][2]['json']['data']['relationships']['user']['data']['id'], 'rec2')
            self.assertEqual(read(cron.AI_NOTED), ['other:70'])
            self.assertEqual(self.stderr().count('no Teamtailor user'), 1)
            # notes for a workspace without a user are skipped, not 404ed one by one
            new = [{'source': 'teamtailor', 'account': 'other', 'candidate_id': '5'}]
            cron.post_teamtailor_notes(new)
            self.assertEqual(new[0]['tt_note'], 'not flagged (no key/user configured)')
            self.assertEqual(len(self.calls), 3)  # no new request
            # a failed lookup is not cached
            cron._note_users.clear()
            self.fake_session_request(lambda m, u, kw: resp(status=500))
            self.assertIsNone(cron.note_user_id('test'))
            self.assertNotIn('test', cron._note_users)

    def test_ai_notes_escape_html_and_dedup(self):
        self.fake_session_request(lambda m, u, kw: resp())
        ai = [{'account': 'test', 'application_id': '10', 'candidate_id': '1', 'user': 'x', 'job': 'Dev <b>&</b>',
               'tool': 'a local tool at http://127.0.0.1:8765/?x=<script>'},
              {'account': 'test', 'application_id': '11', 'candidate_id': '1', 'user': 'x', 'job': None, 'tool': 'the AI job tool Simplify'}]
        cron.post_ai_notes(ai)
        posts = [c for c in self.calls if c[0] == 'POST']
        note = posts[0][2]['json']['data']['attributes']['note']
        self.assertIn('Dev &lt;b&gt;&amp;&lt;/b&gt;', note)
        self.assertIn('&lt;script&gt;', note)
        self.assertNotIn('<script>', note)
        self.assertIn('for a job was submitted via the AI job tool Simplify', posts[1][2]['json']['data']['attributes']['note'])
        self.assertEqual(read(cron.AI_NOTED), ['test:10', 'test:11'])
        cron.post_ai_notes(ai)
        self.assertEqual(len([c for c in self.calls if c[0] == 'POST']), 2)

    def test_tt_request_retries_429_and_get_5xx_only(self):
        seq = iter([resp(status=429, headers={'Retry-After': '1'}), resp(status=500), resp({'ok': 1})])
        self.fake_session_request(lambda m, u, kw: next(seq))
        r = cron.tt_request(cron.tt_session('test'), 'GET', API + '/x')
        self.assertEqual(r.json(), {'ok': 1})
        self.assertEqual(len(self.calls), 3)
        self.assertIs(cron.tt_session('test'), cron.tt_session('test'))  # one keep-alive session per account
        self.assertIsNone(cron.tt_session('nokey'))

    def test_add_teamtailor_emails(self):
        def handler(m, u, kw):
            if u.endswith('/candidates/7'):
                return resp({'data': {'attributes': {'email': 'c@x'}}})
            return resp({'data': [{'relationships': {'job': {'data': {'id': 'j1'}}}},
                                  {'relationships': {'job': {'data': None}}}],
                         'included': [{'type': 'jobs', 'id': 'j1', 'attributes': {'title': 'Dev'},
                                       'relationships': {'user': {'data': {'id': 'u9'}}}},
                                      {'type': 'users', 'id': 'u9', 'attributes': {'name': 'Rec'}}]})
        self.fake_session_request(handler)
        new = [{'source': 'teamtailor', 'account': 'test', 'candidate_id': '7'},
               {'source': 'teamtailor', 'account': 'test', 'candidate_id': '8', 'candidate_email': 'known@x'},
               {'source': 'slack'}]
        cron.add_teamtailor_emails(new)
        self.assertEqual(new[0]['candidate_email'], 'c@x')
        self.assertEqual(new[0]['tt_jobs'], [('Dev', 'Rec')])
        self.assertEqual(new[1]['candidate_email'], 'known@x')
        self.assertEqual([u.rsplit('/', 2)[-2:] for _, u, _ in self.calls],
                         [['candidates', '7'], ['7', 'job-applications'], ['8', 'job-applications']])
        self.assertEqual(self.calls[1][2]['params'], {'include': 'job.user'})


class TestReferrerFindings(Base):
    def app(self, aid, cid, hours_ago, site=None, url=None, job='j1', naive=False, no_rel=False):
        ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        created = ts.replace(tzinfo=None).isoformat() if naive else ts.isoformat()
        ja = {'id': aid, 'attributes': {'created-at': created, 'referring-site': site, 'referring-url': url},
              'relationships': {'candidate': {'data': {'id': cid}}, 'job': {'data': {'id': job} if job else None}}}
        if no_rel:
            del ja['relationships']
        return ja

    def scan(self, pages, hours=24):
        from extractors.teamtailor_extractor import TeamtailorExtractor
        urls = []

        def fake_get(_self, url, params=None):
            urls.append((url, params))
            if url.endswith('/company'):
                return {'data': {'id': 'ABC'}}
            if url in pages:
                return pages[url]
            if params is not None:
                self.assertEqual(params['sort'], '-created-at')
                self.assertEqual(params['page[size]'], 30)
                self.assertEqual(params['include'], 'candidate,job')
                self.assertEqual(params['fields[jobs]'], 'title')
                self.assertEqual(params['fields[job-applications]'], 'created-at,referring-site,referring-url,candidate,job')
                return pages['first']
            raise AssertionError(f'unexpected fetch {url}')

        with patch.object(TeamtailorExtractor, '_get', fake_get):
            found, ai = cron.referrer_findings(hours=hours)
        return found, ai, urls

    def test_scan(self):
        page1 = {'data': [self.app('a1', 'c1', 1, site='89.167.50.51'),                       # global bare IP -> finding
                          self.app('a2', 'c2', 1, site='127.0.0.1:8765'),                     # local -> note only
                          self.app('a3', 'c3', 2, url='https://www.linkedin.com/posts/simplify-your-cv'),  # path word: nothing
                          self.app('a4', 'c4', 2, site='www.simplify.jobs', naive=True),      # AI tool, naive timestamp
                          self.app('a5', 'c5', 2, site='1.2.3.4', no_rel=True),               # malformed row: skipped
                          {'id': 'a6', 'attributes': {'referring-site': '5.6.7.8'}, 'relationships': {}},  # no created-at
                          {'id': 'a7', 'attributes': {'created-at': 'garbage', 'referring-site': '5.6.7.8'}}],  # bad ts: skipped
                 'included': [{'type': 'candidates', 'id': 'c1', 'attributes': {'first-name': 'Ann', 'last-name': 'Lee', 'email': 'ann@x'}},
                              {'type': 'jobs', 'id': 'j1', 'attributes': {'title': 'Dev'}}],
                 'links': {'next': API + '/job-applications?page2'}}
        page2 = {'data': [self.app('a8', 'c8', 48, site='9.9.9.9')], 'links': {'next': API + '/job-applications?page3'}}
        found, ai, urls = self.scan({'first': page1, API + '/job-applications?page2': page2})

        self.assertEqual([(f['candidate_id'], f['ip'], f['user'], f['company'], f['candidate_email'], f['vpn_operator']) for f in found],
                         [('c1', '89.167.50.51', 'Ann Lee', 'ABC@eu', 'ann@x', 'BARE_IP_REFERRER')])
        self.assertEqual(found[0]['email'], 'tt:test:c1')
        self.assertEqual([(a['application_id'], a['user'], a['tool'], a['job']) for a in ai],
                         [('a2', 'Unknown', 'a local tool at 127.0.0.1', 'Dev'), ('a4', 'Unknown', 'the AI job tool Simplify', 'Dev')])
        self.assertEqual([u.rsplit('/', 1)[-1] for u, _ in urls], ['job-applications', 'company', 'job-applications?page2'])
        self.assertIn('skipped application a7', self.stderr())
        self.assertEqual(cron.FAILURES, [])

    def test_no_finding_means_no_company_lookup_and_offhost_next_is_ignored(self):
        page = {'data': [self.app('a1', 'c1', 1, site='LinkedIn')], 'included': [],
                'links': {'next': 'https://evil.example/v1/job-applications?page2'}}
        found, ai, urls = self.scan({'first': page})
        self.assertEqual((found, ai), ([], []))
        self.assertEqual(len(urls), 1)

    def test_blind_page_and_company_failure_are_counted(self):
        page = {'data': [{'id': 'a1', 'attributes': {'created-at': datetime.now(timezone.utc).isoformat(), 'referring-site': '9.9.9.9'}}],
                'included': [], 'links': {}}
        found, ai, urls = self.scan({'first': page})
        self.assertEqual(found, [])
        self.assertTrue(any('none linked to a candidate' in f for f in cron.FAILURES))
        cron.FAILURES.clear()
        from extractors.teamtailor_extractor import TeamtailorExtractor
        page = {'data': [self.app('a1', 'c1', 1, site='9.9.9.9')], 'included': [], 'links': {}}

        def fake_get(_self, url, params=None):
            if url.endswith('/company'):
                raise RuntimeError('500 boom')
            return page
        with patch.object(TeamtailorExtractor, '_get', fake_get):
            found, ai = cron.referrer_findings()
        self.assertEqual(found, [])
        self.assertTrue(any('company lookup failed' in f for f in cron.FAILURES))

    def test_account_failure_is_isolated_and_counted(self):
        from extractors.teamtailor_extractor import TeamtailorExtractor
        with patch.object(TeamtailorExtractor, '_get', side_effect=RuntimeError('boom')), \
                patch.dict(os.environ, {'TEAMTAILOR_API_KEY_OTHER': 'k2'}):
            found, ai = cron.referrer_findings()
        self.assertEqual((found, ai), ([], []))
        self.assertEqual(len(cron.FAILURES), 2)
        self.assertEqual(self.stderr().count('referrer check failed'), 2)


class TestSlackPost(Base):
    def test_retries_transient_errors_then_raises_without_the_url(self):
        seq = iter([resp(status=429, headers={'Retry-After': '2'}), resp(status=503), resp(status=200)])
        with patch.object(cron.requests, 'post', side_effect=lambda *a, **k: next(seq)) as post:
            cron.post_slack('https://hooks.example/secret', {'text': 'hi'})
        self.assertEqual(post.call_count, 3)
        with patch.object(cron.requests, 'post', return_value=resp(status=404, text='no_service')):
            with self.assertRaisesRegex(RuntimeError, 'no_service') as cm:
                cron.post_slack('https://hooks.example/secret', {'text': 'hi'})
        self.assertNotIn('secret', str(cm.exception))
        err = cron.requests.ConnectionError('HTTPSConnectionPool: Max retries exceeded with url: /secret')
        with patch.object(cron.requests, 'post', side_effect=err) as post:
            with self.assertRaises(RuntimeError) as cm:
                cron.post_slack('https://hooks.example/secret', {'text': 'hi'})
        self.assertEqual(post.call_count, 4)
        self.assertNotIn('secret', str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)
        self.assertTrue(cm.exception.__suppress_context__)

    def test_rejected_blocks_fall_back_to_plain_text(self):
        seq = iter([resp(status=400, text='invalid_blocks'), resp(status=200)])
        with patch.object(cron.requests, 'post', side_effect=lambda *a, **k: next(seq)) as post:
            cron.post_slack('https://hooks.example/x', {'text': 'fallback', 'blocks': [{'type': 'bad'}]})
        self.assertEqual(post.call_count, 2)
        self.assertEqual(post.call_args.kwargs['json'], {'text': 'fallback'})
        self.assertIn('invalid_blocks', self.stderr())
        self.assertEqual(len(cron.FAILURES), 1)  # the broken blocks must not stay invisible

    def test_read_timeout_is_not_retried(self):
        with patch.object(cron.requests, 'post', side_effect=cron.requests.ReadTimeout('slow /secret')) as post:
            with self.assertRaises(RuntimeError) as cm:
                cron.post_slack('https://hooks.example/secret', {'text': 'hi'})
        self.assertEqual(post.call_count, 1)  # the message may have been delivered; never double-post
        self.assertNotIn('secret', str(cm.exception))


class TestDetector(Base):
    def test_success_forwards_stderr_and_counts_source_failures(self):
        done = subprocess.CompletedProcess(args=[], returncode=0, stdout='progress',
                                           stderr='   ⚠️  Teamtailor (dk) extraction failed: 401\nsome warning\n')
        with patch.object(cron.subprocess, 'run', return_value=done) as run:
            elapsed = cron.run_detector()
        self.assertGreaterEqual(elapsed, 0)
        self.assertEqual(run.call_args.kwargs['timeout'], cron.DETECTOR_TIMEOUT)
        self.assertIn('--days', run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][-1], cron.REPORT)
        self.assertEqual(len(cron.FAILURES), 1)
        with patch.object(cron.subprocess, 'run', return_value=done) as run:
            cron.run_detector('/tmp/elsewhere.json')
        self.assertEqual(run.call_args.args[0][-1], '/tmp/elsewhere.json')
        self.assertEqual(len(cron.FAILURES), 2)
        self.assertIn('detector:    ⚠️  Teamtailor (dk) extraction failed: 401', self.stderr())
        self.assertIn('detector: some warning', self.stderr())

    def test_failure_and_timeout_exit_1(self):
        bad = subprocess.CompletedProcess(args=[], returncode=1, stdout='', stderr='❌ Error: x')
        with patch.object(cron.subprocess, 'run', return_value=bad):
            with self.assertRaises(SystemExit) as cm:
                cron.run_detector()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn('detector failed (exit 1)', self.stderr())
        exc = subprocess.TimeoutExpired(cmd='x', timeout=1, output=b'out\xff', stderr=b'err')
        with patch.object(cron.subprocess, 'run', side_effect=exc):
            with self.assertRaises(SystemExit) as cm:
                cron.run_detector()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn('killed after', self.stderr())
        self.assertIn('out\ufffd\nerr', self.stderr())


class TestMain(Base):
    def report(self, anomalies):
        path = os.path.join(self.tmp, 'report.json')
        with open(path, 'w') as f:
            json.dump({'summary': {'slack_entries': 1, 'zoom_entries': 2, 'teamtailor_entries': 3}, 'anomalies': anomalies}, f)
        return path

    @staticmethod
    def tt_get_or_post(method, url, kw):
        if method != 'GET':
            return resp()
        if url.endswith('/job-applications'):
            return resp({'data': [], 'included': []})
        return resp({'data': {'attributes': {'email': 'c@x'}}})

    def anomaly(self, **kw):
        base = {'user': 'Ann', 'email': 'tt:test:1', 'candidate_id': '1', 'account': 'test', 'company': 'ABC@eu',
                'ip': '1.2.3.4', 'vpn_operator': 'ASTRILL_VPN', 'source': 'teamtailor'}
        base.update(kw)
        return base

    def test_dry_run_has_no_side_effects(self):
        self.fake_session_request(self.tt_get_or_post)
        out = io.StringIO()
        with patch.object(sys, 'argv', ['x', self.report([self.anomaly()]), '--dry-run']), \
                patch.object(cron.requests, 'post') as post, patch.object(cron, 'run_detector') as det, \
                patch.object(cron, 'referrer_findings') as ref, redirect_stdout(out):
            cron.main()
        self.assertFalse(post.called)
        self.assertFalse(det.called)
        self.assertFalse(ref.called)
        self.assertEqual([m for m, _, _ in self.calls], ['GET', 'GET'])  # read-only lookups only
        self.assertFalse(os.path.exists(cron.STATE))
        self.assertFalse(os.path.exists(cron.NOTED))
        self.assertFalse(os.path.exists(cron.LOCK))
        self.assertIn('dry run, not flagged', out.getvalue())
        self.assertIn('"blocks"', out.getvalue())

    def test_replay_posts_notes_then_slack_then_saves_state(self):
        self.fake_session_request(self.tt_get_or_post)
        out = io.StringIO()
        report = self.report([self.anomaly(),
                              {'user': 'jirabot', 'email': 'Unknown', 'ip': '9.9.9.9', 'vpn_operator': 'KASM_VDI', 'source': 'slack'},
                              self.anomaly(user='jirabot', email='tt:test:9', candidate_id='9')])  # applicant-typed name: still alerts
        with patch.object(sys, 'argv', ['x', report]), patch.object(cron.requests, 'post', return_value=resp()) as post, \
                redirect_stdout(out):
            cron.main()
        self.assertEqual(post.call_count, 1)
        payload = post.call_args.kwargs['json']
        self.assertEqual(payload['blocks'][0]['text']['text'], '🚨 2 new VPN/proxy detections')
        self.assertIn('_profile flagged_', json.dumps(payload, ensure_ascii=False))
        self.assertEqual(read(cron.STATE), ['tt:test:1|1.2.3.4|ASTRILL_VPN|teamtailor', 'tt:test:9|1.2.3.4|ASTRILL_VPN|teamtailor'])
        self.assertEqual(read(cron.NOTED), ['test:1', 'test:9'])
        self.assertRegex(out.getvalue(), r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d[+-]\d{4} report .*: slack 1 zoom 2 teamtailor 3 anomalies 3')
        self.assertRegex(out.getvalue(), r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d[+-]\d{4} posted 2 new finding\(s\) to Slack')

        # second replay: nothing new, no post, state untouched, lock free again
        with patch.object(sys, 'argv', ['x', self.report([self.anomaly()])]), \
                patch.object(cron.requests, 'post') as post2, redirect_stdout(io.StringIO()):
            cron.main()
        self.assertFalse(post2.called)
        cron.release_lock(cron.acquire_lock())

    def test_slack_failure_keeps_state_for_retry(self):
        self.fake_session_request(self.tt_get_or_post)
        with patch.object(sys, 'argv', ['x', self.report([self.anomaly()])]), \
                patch.object(cron.requests, 'post', return_value=resp(status=403, text='invalid_token')), redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                cron.main()
        self.assertFalse(os.path.exists(cron.STATE))
        self.assertEqual(read(cron.NOTED), ['test:1'])  # note stays recorded: never posted twice
        cron.release_lock(cron.acquire_lock())  # lock released even though the run raised

    def test_missing_webhook_fails_before_any_side_effect(self):
        self.fake_session_request(lambda m, u, kw: resp())
        env = {k: v for k, v in os.environ.items() if k != 'SLACK_WEBHOOK_URL'}
        with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['x', self.report([self.anomaly()])]):
            with self.assertRaises(SystemExit) as cm:
                cron.main()
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(self.calls, [])
        self.assertFalse(os.path.exists(cron.NOTED))

    def test_live_dry_run_uses_its_own_report_file(self):
        self.fake_session_request(self.tt_get_or_post)
        dry = os.path.join(self.tmp, 'dry.json')
        bare = [self.anomaly(candidate_id='5', email='tt:test:5', vpn_operator='BARE_IP_REFERRER', candidate_email='k@x')]
        ai = [{'account': 'test', 'application_id': '77', 'candidate_id': '5', 'user': 'x', 'job': 'Dev', 'tool': 'a local tool at http://127.0.0.1/\x1b[31m'}]
        out = io.StringIO()
        with patch.object(cron, 'DRY_RUN_REPORT', dry), patch.object(sys, 'argv', ['x', '--dry-run']), \
                patch.object(cron, 'run_detector', side_effect=lambda out: os.replace(self.report([]), out) or 0.5) as det, \
                patch.object(cron, 'referrer_findings', return_value=(bare, ai)), patch.object(cron.requests, 'post') as post, \
                redirect_stdout(out):
            cron.main()
        self.assertEqual(det.call_args.args[0], dry)
        self.assertFalse(os.path.exists(cron.REPORT))
        self.assertFalse(post.called)
        self.assertEqual([m for m, _, _ in self.calls], ['GET'])  # jobs lookup only: email came from the scan, no POST
        self.assertFalse(os.path.exists(cron.AI_NOTED))
        self.assertFalse(os.path.exists(cron.NOTED))
        self.assertFalse(os.path.exists(cron.STATE))
        self.assertIn('would note application test:77 (a local tool at http://127.0.0.1/[31m)', out.getvalue())  # ESC stripped
        self.assertIn('"blocks"', out.getvalue())
        self.assertTrue(os.path.exists(cron.LOCK))  # a live dry run takes the lock

    def test_missing_note_user_only_warns(self):
        env = {k: v for k, v in os.environ.items() if k != 'TEAMTAILOR_NOTE_USER_ID'}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(cron.check_config(dry_run=False), 'https://hooks.example/x')
        self.assertIn('TEAMTAILOR_NOTE_USER_ID is not set', self.stderr())

    def test_second_concurrent_run_exits_nonzero(self):
        fd = cron.acquire_lock()
        try:
            with patch.object(sys, 'argv', ['x', self.report([])]):
                with self.assertRaises(SystemExit) as cm:
                    cron.main()
            self.assertEqual(cm.exception.code, 1)
        finally:
            cron.release_lock(fd)

    def test_non_fatal_failures_exit_1_after_the_work_is_done(self):
        self.fake_session_request(self.tt_get_or_post)

        def failing_scan():
            cron.fail('teamtailor referrer check failed for x: boom')
            return [], []

        with patch.object(sys, 'argv', ['x']), patch.object(cron, 'run_detector', return_value=1.0), \
                patch.object(cron, 'REPORT', self.report([self.anomaly()])), \
                patch.object(cron, 'referrer_findings', failing_scan), \
                patch.object(cron.requests, 'post', return_value=resp()) as post, redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                cron.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(post.call_count, 1)  # the alert was still posted ...
        self.assertTrue(os.path.exists(cron.STATE))  # ... and remembered
        self.assertIn('1 non-fatal failure(s)', self.stderr())


if __name__ == '__main__':
    unittest.main(verbosity=1)
