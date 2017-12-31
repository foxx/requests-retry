#!/usr/bin/env python3

"""
Requests Retry

This module implements retry logic into requests.Session.

Although this can be done using max_retries, the underlying class (urllib3.util.Retry)
is very limited in functionality and doesn't work for complex use cases. For example,
if you have multiple threads using the same session

max_retries=urllib3.util.Retry()
"""

import time
import requests
import email
import re
import logging
import threading

from contextlib import contextmanager

logger = logging.getLogger(__name__)

STATUS_CODES_2XX = frozenset(range(200, 300))
STATUS_CODES_3XX = frozenset(range(300, 400))
STATUS_CODES_4XX = frozenset(range(400, 500))
STATUS_CODES_5XX = frozenset(range(500, 600))

STATUS_CODES_4XX_5XX = frozenset.union(STATUS_CODES_4XX, STATUS_CODES_5XX)
IDEMPOTENT_METHODS = frozenset(['HEAD', 'GET', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'])

DEFAULT_RR_MAX_RETRIES = 3
DEFAULT_RR_RETRY_DELAY = 3

CONNECTION_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.ContentDecodingError,
    requests.exceptions.StreamConsumedError,
    requests.exceptions.UnrewindableBodyError,
    requests.exceptions.TooManyRedirects)


class RetryInfo:
    def __init__(self):
        self.total_retries = 0
        self.total_timeout_retries = 0
        self.total_connection_retries = 0
        self.total_rule_retries = 0
        self.history = []


class SessionRetryMixin(requests.Session):

    def request(self, *args, **kwargs):
        retry = getattr(self, 'retry', None)
        assert isinstance(retry, SessionRetry)

        ri = RetryInfo()

        while True:
            last_exc = None

            # once any of our maximums have been reached, stop retry
            if (ri.total_retries >= self.retry.max_retries or
                ri.total_timeout_retries >= self.retry.max_timeout_retries or
                ri.total_connection_retries >= self.retry.max_connection_retries or
                ri.total_rule_retries >= self.retry.max_rule_retries):

                # raise new exception
                exc = requests.exceptions.RetryError()
                exc.retry = ri
                raise exc

            # are we currently waiting for another request in this session to
            # finish its backoff? this prevents us from hammering the endpoint
            # with concurrent requests when we know others are in backoff
            self.retry.lock.wait_until_ready()

            try:
                resp = super(SessionRetryMixin, self).request(*args, **kwargs)
            except requests.exceptions.Timeout as exc:
                ri.total_timeout_retries += 1
                last_exc = exc
            except CONNECTION_ERRORS as exc:
                ri.total_connection_retries += 1
                last_exc = exc
            except Exception as exc:
                raise

            # problem during request
            if last_exc:
                ri.history += [last_exc]
                ri.total_retries += 1
                self.retry.backoff(last_exc.request)
                continue 

            # did we encounter any retry logic?
            if not self.retry.process_rules(resp.request, resp):
                ri.history += [resp]
                resp.retry = ri
                return resp

            ri.total_rule_retries += 1
            ri.total_retries += 1


class RetryRule:
    default_methods = IDEMPOTENT_METHODS
    default_status_codes = STATUS_CODES_4XX_5XX
    default_max_retries = DEFAULT_RR_MAX_RETRIES
    default_retry_delay = DEFAULT_RR_RETRY_DELAY

    def __init__(self, methods=None, status_codes=None, max_retries=None, retry_delay=None):
        self.methods = frozenset(methods if methods else self.default_methods)
        self.status_codes = frozenset(status_codes if status_codes else self.default_status_codes)
        self.max_retries = max_retries if max_retries else self.default_max_retries
        self.retry_delay = retry_delay if retry_delay else self.default_retry_delay

    def is_match(self, request, response):
        """
        Check whether rule should be applied to this request/response

        Returns True if this rule matches, otherwise False
        """
        assert isinstance(request, requests.PreparedRequest)
        assert isinstance(response, requests.Response)

        if response.status_code not in self.status_codes:
            return False
        if request.method not in self.methods:
            return False
        return True

    def handle(self, request, response):
        self.backoff(self.retry_delay)

    def backoff(self, seconds):
        logger.debug('rule backing off for {:.2f}s'.format(seconds))
        time.sleep(seconds)


class RetryRuleRetryAfter(RetryRule):

    def parse_retry_after(self, retry_after):
        """
        Taken from urllib3/util/retry.py#L217
        """
        # Whitespace: https://tools.ietf.org/html/rfc7230#section-3.2.4
        if re.match(r"^\s*[0-9]+\s*$", retry_after):
            seconds = int(retry_after)
        else:
            retry_date_tuple = email.utils.parsedate(retry_after)
            if retry_date_tuple is None:
                raise requests.exceptions.InvalidHeader(
                    "Invalid Retry-After header: %s" % retry_after)
            retry_date = time.mktime(retry_date_tuple)
            seconds = retry_date - time.time()

        if seconds < 0:
            seconds = 0

        return seconds

    def is_match(self, request, response):
        is_match = super(RetryRuleRetryAfter, self).is_match(request, response)
        if not is_match:
            return False
        return 'Retry-After' in response.headers

    def handle(self, request, response):
        retry_after = response.headers.get('Retry-After')
        retry_after = self.parse_retry_after(retry_after) if retry_after else None
        if retry_after:
            msg = 'Retry-After: requested to backoff for {:.2f}s'.format(retry_after)
            time.sleep(retry_after)


class SessionRetry:
    """
    Retry logic for requests.Session()
    XXX: add docstring
    """
    DEFAULT_SR_MAX_CONNECTION_RETRIES = 3
    DEFAULT_SR_MAX_TIMEOUT_RETRIES = 3
    DEFAULT_SR_MAX_RULE_RETRIES = 3
    DEFAULT_SR_MAX_RETRIES = 3
    DEFAULT_SR_RETRY_BACKOFF = 2
    DEFAULT_RULES = frozenset([RetryRuleRetryAfter()])

    def __init__(self, rules=DEFAULT_RULES,
                 max_connection_retries=DEFAULT_SR_MAX_CONNECTION_RETRIES,
                 max_timeout_retries=DEFAULT_SR_MAX_TIMEOUT_RETRIES,
                 max_rule_retries=DEFAULT_SR_MAX_RULE_RETRIES,
                 max_retries=DEFAULT_SR_MAX_RETRIES,
                 retry_backoff=DEFAULT_SR_RETRY_BACKOFF,
                 share_backoff=True):

        assert isinstance(max_connection_retries, int)
        assert isinstance(max_timeout_retries, int)
        assert isinstance(max_rule_retries, int)
        assert isinstance(max_retries, int)
        assert isinstance(retry_backoff, int)
        assert isinstance(share_backoff, bool)

        self.rules = list(rules)
        self.max_connection_retries = max_connection_retries
        self.max_timeout_retries = max_timeout_retries
        self.max_rule_retries = max_rule_retries
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.share_backoff = share_backoff
        self.lock = RetryLock()

    def install(self, session):
        assert isinstance(session, requests.Session)

        base_cls = session.__class__
        base_cls_name = session.__class__.__name__
        session.__class__ = type(base_cls_name, (SessionRetryMixin, base_cls),{})
        session.retry = self

    def process_rules(self, request, response):
        """
        Find the first matching rule, process it and return it
        """

        with self.lock.lock():
            for rule in self.rules:
                if not isinstance(rule, RetryRule):
                    raise ValueError('expected instance of RetryRule, got {}'.format(rule))

                if rule.is_match(request, response):
                    rule.handle(request, response)
                    return rule
            return False

    def backoff(self, request):
        """
        Suspend other requests if we are currently backing off
        """
        with self.lock.lock():
            logger.debug('backing off for {:.2f}s'.format(self.retry_backoff))
            time.sleep(self.retry_backoff)


class RetryLock:
    """
    XXX: Lock debug should print out request ID
    """
    def __init__(self):
        self.event = threading.Event()
        self.event.set()

        self.condition = threading.Condition(lock=threading.Lock())
        self.current_req = None

    @contextmanager
    def lock(self):
        # check whether another lock is already set
        acquired = self.condition.acquire(False)
        if not acquired:
            logger.debug('request is waiting to acquire lock')
            self.condition.acquire()

        self.event.clear()
        logger.debug('request has acquired lock')

        try:
            yield
        finally:
            self.condition.release()
            self.event.set()
            logger.debug('request has released lock')
    
    def wait_until_ready(self):
        if not self.event.is_set():
            logger.debug('request waiting for lock to be released')
            ts = time.time()
            self.event.wait()
            taken = time.time() - ts
            logger.debug('request finished waiting for lock to be '
                         'released, took {:.2f}s'.format(taken))


