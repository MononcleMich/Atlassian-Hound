import logging
import threading
import time
from functools import lru_cache
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


LOG = logging.getLogger("AtlassianHound.http")
_SESSION_LOCK = threading.Lock()


def _build_retry(total: int = 5, backoff: float = 0.5) -> Retry:
    return Retry(
        total=total,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
    )


def _configure_session(session: requests.Session, *, timeout: Optional[float] = None, pool_size: int = 20, max_retries: int = 5, backoff: float = 0.5) -> requests.Session:
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=_build_retry(total=max_retries, backoff=backoff),
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if timeout is not None:
        session.request = _wrap_request_with_timeout(session.request, timeout)  # type: ignore[method-assign]
    return session


def _wrap_request_with_timeout(request_func, timeout: float):
    def wrapper(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return request_func(method, url, **kwargs)

    return wrapper


@lru_cache(maxsize=1)
def get_session(timeout: Optional[float] = 30.0) -> requests.Session:
    from utils import common

    with _SESSION_LOCK:
        pool_size = getattr(common, "HTTP_POOL_SIZE", 20)
        max_retries = getattr(common, "HTTP_MAX_RETRIES", 5)
        backoff = getattr(common, "HTTP_BACKOFF_FACTOR", 0.5)

        LOG.debug("Creating shared HTTP session (timeout=%s, pool=%d, retries=%d).", timeout, pool_size, max_retries)
        session = requests.Session()
        return _configure_session(session, timeout=timeout, pool_size=pool_size, max_retries=max_retries, backoff=backoff)


def handle_http_error(resp: requests.Response, context: str = "") -> bool:
    """
    Log friendly HTTP error messages for optional endpoints.
    Returns True if the caller should retry the request (rate limit), False otherwise.
    """
    code = getattr(resp, "status_code", None)
    reason = getattr(resp, "reason", "")
    url = getattr(resp, "url", "")
    prefix = f"{context}: " if context else ""
    message = f"{prefix}HTTP {code} - {reason} ({url})"

    if code == 429:
        retry_after = resp.headers.get("Retry-After", "60")
        try:
            wait_seconds = int(retry_after)
        except ValueError:
            wait_seconds = 60
        LOG.warning("%s -> Rate limited. Waiting %d seconds before retry...", message, wait_seconds)
        time.sleep(wait_seconds)
        return True  # Signal to retry
    elif code == 401:
        LOG.warning("%s -> Unauthorized (check API token permissions)", message)
    elif code == 403:
        LOG.warning("%s -> Forbidden (insufficient privileges)", message)
    elif code == 404:
        LOG.info("%s -> Endpoint not found (likely unsupported on this Atlassian Cloud tier)", message)
    elif code == 400:
        LOG.warning("%s -> Bad request (verify syntax or access scope)", message)
    else:
        LOG.warning("%s -> %s", message, getattr(resp, "text", "")[:200])

    return False  # Don't retry
