import time
import requests
import pytest
import logging

from requests_retry import SessionRetry, SessionRetryMixin
from requests_retry import RetryRule, RetryRuleRetryAfter
from requests_retry import RetryLock

from freezegun import freeze_time
from unittest import mock

import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

######################################################################
# HELPERS
######################################################################

def make_req_resp_pair(method, status_code):
    req = requests.Request(method=method, url='https://example.com')

    resp = requests.Response()
    resp.status_code = status_code
    resp.request = req.prepare()

    return (resp.request, resp)


######################################################################
# RETRY RULES
######################################################################

class TestRetryRule:
    def setup_method(self):
        self.rr = RetryRule(methods=['GET'], status_codes=[200], 
            max_retries=3, retry_delay=2)

    def test_assignment(self):
        # check assignment
        assert self.rr.methods == frozenset(['GET'])
        assert self.rr.status_codes == frozenset([200])
        assert self.rr.max_retries == 3
        assert self.rr.retry_delay == 2

    def test_is_match(self):
        # good status, bad method, don't retry
        req, resp = make_req_resp_pair('POST', 200)
        assert self.rr.is_match(req, resp) == False

        # bad status, good method, don't retry
        req, resp = make_req_resp_pair('GET', 400)
        assert self.rr.is_match(req, resp) == False

        # bad status, bad method, don't retry
        req, resp = make_req_resp_pair('POST', 400)
        assert self.rr.is_match(req, resp) == False

        # good status, good method, retry
        req, resp = make_req_resp_pair('GET', 200)
        assert self.rr.is_match(req, resp) == True

    def test_handle(self):
        req, resp = make_req_resp_pair('GET', 200)

        with mock.patch('time.sleep') as p:
            self.rr.handle(req, resp)
            p.assert_called_once_with(2)


class TestRetryRuleRetryAfter:
    def setup_method(self):
        self.rr = RetryRuleRetryAfter()

    def test_parse_retry_after(self):
        rr = self.rr
        assert rr.parse_retry_after('30') == 30
        assert rr.parse_retry_after('Fri, 31 Dec 1999 23:59:52 GMT') == 0
        with freeze_time('Fri, 31 Dec 1999 23:59:50 GMT'):
            assert rr.parse_retry_after('Fri, 31 Dec 1999 23:59:49 GMT') == 0
            assert rr.parse_retry_after('Fri, 31 Dec 1999 23:59:50 GMT') == 0
            assert rr.parse_retry_after('Fri, 31 Dec 1999 23:59:52 GMT') == 2

        # invalid date
        with pytest.raises(requests.exceptions.InvalidHeader) as exc:
            assert rr.parse_retry_after('invalid')

    def test_is_match(self):
        rr = self.rr

        # good status, bad method, don't retry
        req, resp = make_req_resp_pair('POST', 200)
        resp.headers['Retry-After'] = 30
        assert rr.is_match(req, resp) == False

        # bad status, good method, don't retry
        req, resp = make_req_resp_pair('GET', 200)
        resp.headers['Retry-After'] = 30
        assert rr.is_match(req, resp) == False

        # bad status, bad method, don't retry
        req, resp = make_req_resp_pair('POST', 200)
        resp.headers['Retry-After'] = 30
        assert rr.is_match(req, resp) == False

        # good status, good method, bad header, don't retry
        req, resp = make_req_resp_pair('GET', 400)
        assert rr.is_match(req, resp) == False

        # good status, good method, retry
        req, resp = make_req_resp_pair('GET', 400)
        resp.headers['Retry-After'] = 30
        assert rr.is_match(req, resp) == True

    def test_handle(self):
        rr = self.rr
        req, resp = make_req_resp_pair('GET', 200)

        with freeze_time('Fri, 31 Dec 1999 23:59:50 GMT'):
            # no retry-header, so rule doesn't apply
            with mock.patch('time.sleep') as p:
                rr.handle(req, resp)
                p.assert_not_called()

            # retry-after header present, but zero, no sleep
            with mock.patch('time.sleep') as p:
                resp.headers['Retry-After'] = '0'
                rr.handle(req, resp)
                p.assert_not_called()

            # retry-after header present, should sleep
            with mock.patch('time.sleep') as p:
                resp.headers['Retry-After'] = '27'
                rr.handle(req, resp)
                p.assert_called_once_with(27)


######################################################################
# SESSION RETRY
######################################################################

class TestSessionRetry:
    def setup_method(self):
        self.sr = SessionRetry()

    def test_install(self):
        session = requests.Session()
        assert session.request.__func__ != SessionRetryMixin.request

        sr = SessionRetry()
        sr.install(session)
        assert session.request.__func__ == SessionRetryMixin.request

    def test_rule_instance(self):
        """Detect when rules have not been instantiated"""
        session = requests.Session()
        sr = SessionRetry()
        sr.rules = [RetryRuleRetryAfter]
        sr.install(session)

        req, resp = make_req_resp_pair('GET', 400)
        with pytest.raises(ValueError):
            sr.process_rules(req, resp)

    def test_default_assignment(self):
        assert self.sr.rules == list(SessionRetry.DEFAULT_RULES)
        assert self.sr.max_connection_retries == 3
        assert self.sr.max_timeout_retries == 3
        assert self.sr.max_rule_retries == 3
        assert self.sr.max_retries == 3
        assert self.sr.retry_backoff == 2
 
    def test_assignment(self):
        sr = SessionRetry(rules=[], max_connection_retries=1, max_timeout_retries=2,
                          max_rule_retries=3, max_retries=4, retry_backoff=5)
        assert sr.rules == []
        assert sr.max_connection_retries == 1
        assert sr.max_timeout_retries == 2
        assert sr.max_rule_retries == 3
        assert sr.max_retries == 4
        assert sr.retry_backoff == 5

    def test_process_rules_default(self):
        req, resp = make_req_resp_pair('GET', 400)

        with freeze_time('Fri, 31 Dec 1999 23:59:50 GMT'):

            # no retry-header, so rule doesn't apply
            with mock.patch('time.sleep') as p:
                result = self.sr.process_rules(req, resp)
                assert result is False
                p.assert_not_called()

            # retry-after header present, should sleep
            with mock.patch('time.sleep') as p:
                resp.headers['Retry-After'] = '28'
                result = self.sr.process_rules(req, resp)
                assert result is list(self.sr.rules)[0]
                p.assert_called_once_with(28)

    def test_process_rules_block_next(self):
        req, resp = make_req_resp_pair('GET', 400)

        session = requests.Session()
        sr = SessionRetry(rules=[RetryRuleRetryAfter(), RetryRuleRetryAfter()])
        sr.install(session)
        result = self.sr.process_rules(req, resp)

        # only one rule should be called
        with mock.patch('time.sleep') as p:
            resp.headers['Retry-After'] = '28'
            result = sr.process_rules(req, resp)
            assert result is list(sr.rules)[0]
            p.assert_called_once_with(28)


class TestSessionRetryMixin:
    def setup_method(self):
        self.session = requests.Session()
        self.sr = SessionRetry()
        self.sr.install(self.session)

    def test_retry_raise_exception(self):
        """Raise any errors that relate to values/types etc"""
        expect_exc = requests.exceptions.InvalidSchema()
        patch_req = mock.patch('requests.Session.request', side_effect=expect_exc)
        patch_sleep = mock.patch('time.sleep')

        with patch_req as pr, patch_sleep as ps:
            with pytest.raises(requests.exceptions.InvalidSchema) as exc:
                self.session.get('https://example.com')


    def test_retry_connection_error_exceeded(self):
        """Too many connection errors"""
        expect_exc = requests.exceptions.ConnectionError()
        patch_req = mock.patch('requests.Session.request', side_effect=expect_exc)
        patch_sleep = mock.patch('time.sleep')

        with patch_req as pr, patch_sleep as ps:
            with pytest.raises(requests.exceptions.RetryError) as exc:
                self.session.get('https://example.com')
            assert set(exc.value.retry.history) == set([expect_exc])

            # check retry counts
            assert pr.call_count == self.sr.max_connection_retries
            assert exc.value.retry.total_connection_retries == self.sr.max_connection_retries
            assert exc.value.retry.total_retries == self.sr.max_connection_retries
            assert exc.value.retry.total_timeout_retries == 0
            assert exc.value.retry.total_rule_retries == 0

            # sleep (backoff) should have been called on each retry
            assert ps.call_count == self.sr.max_connection_retries

    def test_retry_timeout_error_exceeded(self):
        """Too many timeout errors"""
        expect_exc = requests.exceptions.Timeout()
        patch_req = mock.patch('requests.Session.request', side_effect=expect_exc)
        patch_sleep = mock.patch('time.sleep')

        with patch_req as pr, patch_sleep as ps:
            with pytest.raises(requests.exceptions.RetryError) as exc:
                self.session.get('https://example.com')
            assert set(exc.value.retry.history) == set([expect_exc])

            # check retry counts
            assert pr.call_count == self.sr.max_timeout_retries
            assert exc.value.retry.total_connection_retries == 0
            assert exc.value.retry.total_retries == self.sr.max_timeout_retries
            assert exc.value.retry.total_timeout_retries == self.sr.max_timeout_retries
            assert exc.value.retry.total_rule_retries == 0

            # sleep (backoff) should have been called on each retry
            assert ps.call_count == self.sr.max_timeout_retries

    def test_retry_rule_no_match(self):
        """No retry rule match"""
        req, resp = make_req_resp_pair('GET', 400)
        patch_req = mock.patch('requests.Session.request', return_value=resp)
        patch_sleep = mock.patch('time.sleep')

        # retry-after not present, so no retry should happen
        with patch_req as pr, patch_sleep as ps:
            resp = self.session.get('https://example.com')

            # check retry counts
            assert pr.call_count == 1
            assert resp.retry.total_connection_retries == 0
            assert resp.retry.total_retries == 0
            assert resp.retry.total_timeout_retries == 0
            assert resp.retry.total_rule_retries == 0

            # sleep (backoff) should never be called here
            assert ps.call_count == 0

    def test_retry_rule_match_exceeded(self):
        """Too many retry failures on rule match"""
        req, resp = make_req_resp_pair('GET', 400)
        resp.headers['Retry-After'] = '30'
        patch_req = mock.patch('requests.Session.request', return_value=resp)
        patch_sleep = mock.patch('time.sleep')

        # retry-after not present, so no retry should happen
        with patch_req as pr, patch_sleep as ps:
            with pytest.raises(requests.exceptions.RetryError) as exc:
                self.session.get('https://example.com')

            # check retry counts
            assert exc.value.retry.total_connection_retries == 0
            assert exc.value.retry.total_retries == self.sr.max_rule_retries
            assert exc.value.retry.total_timeout_retries == 0
            assert exc.value.retry.total_rule_retries == self.sr.max_rule_retries

            # sleep (backoff) should be called
            assert ps.call_count == self.sr.max_rule_retries

    # XXX: mark as live request
    def test_live_request(self):
        self.session.get('https://api.github.com')

    def test_concurrent_retry_lock(self):
        """
        XXX: This doesn't validate our locking semantics, needs improvement
        XXX: patch make_req_resp_pair() to use real request passed in
        """
        # fake our sleep call (to speed up testing)
        osleep = time.sleep
        mock_sleep = mock.patch('time.sleep', side_effect=lambda x: osleep(0.2))

        # fake request/response
        def make_request(method, url, *args, **kwargs):
            req, resp = make_req_resp_pair('GET', 400)
            if url.endswith('/retry'):
                resp.headers['Retry-After'] = '30'
            return resp
        mock_request = mock.patch('requests.Session.request', side_effect=make_request)

        with mock_sleep, mock_request:
            # create concurrent pool
            tpe = ThreadPoolExecutor(max_workers=4)
            futures = []

            # first request always triggers retry
            future = tpe.submit(self.session.get, 'https://example.com/retry')
            futures += [future]

            # subsequent requests dont trigger retry
            for x in range(tpe._max_workers-1):
                future = tpe.submit(self.session.get, 'https://example.com/')
                futures += [future]

            concurrent.futures.wait(futures)
            for future in futures:
                future.exception()
                #future.result()


class TestRetryLock:
    def test_all(self):
        req1, resp1 = make_req_resp_pair('GET', 400)
        req2, resp2 = make_req_resp_pair('GET', 400)

        rl = RetryLock()
        with rl.lock():
            pass


def test_logging():
    logging.debug('debug')
    logging.info('info')
    logging.warning('warning')
    logging.error('error')
