"""Explicit deployment binding for the pinned A2A TCK's HTTP+JSON factory.

Put this directory on PYTHONPATH and load with ``pytest -p a2a_tck_deployment``.
Set A2A_TCK_SUT_URL and pass the same canonical URL to --sut-host. Optional
A2A_TCK_TENANT, A2A_TCK_BEARER_TOKEN_FILE and A2A_TCK_CA_FILE configure only
the transport client. Agent Card discovery remains the stock public fixture.
Interface URLs must match the configured base or its
declared tenant scope. Tokens are at most 4096 ASCII characters; CA files contain
only PEM certificates and are at most 262144 bytes. Empty options are invalid.
"""

from __future__ import annotations

import inspect
import ipaddress
import os
import re
import ssl
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

import httpx
import pytest

from tck.transport.base import StreamingResponse, TransportResponse
from tck.transport.http_json_client import (
    PATH_MESSAGE_SEND,
    PATH_MESSAGE_STREAM,
    HttpJsonClient,
)


class DeploymentError(pytest.UsageError):
    """A bounded deployment diagnostic that never includes input values."""


def _fail(reason: str) -> NoReturn:
    raise DeploymentError(f"A2A TCK deployment: {reason}") from None


def _canonical_url(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 2048
        or not value.isascii()
        or re.search(r"[\s\\?#%]", value)
    ):
        _fail("SUT and interface URLs must be canonical ASCII HTTP(S) URLs")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        _fail("invalid URL authority")
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65535)
    ):
        _fail("invalid URL authority")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            _fail("invalid canonical hostname")
        if re.fullmatch(r"[0-9.]+", host):
            _fail("noncanonical IP address")
        canonical_host = host
        loopback = host == "localhost"
    else:
        canonical_host = (
            f"[{address.compressed}]" if address.version == 6 else str(address)
        )
        loopback = address.is_loopback
    if parsed.scheme != "https" and not loopback:
        _fail("HTTPS is required outside loopback")
    if port == (443 if parsed.scheme == "https" else 80):
        _fail("default ports must be omitted")
    authority = canonical_host + (f":{port}" if port is not None else "")
    path = parsed.path
    checked_path = path.rstrip("/")
    if path and (
        not path.startswith("/")
        or "//" in path
        or any(
            not re.fullmatch(r"[A-Za-z0-9._~-]+", segment)
            or segment in {".", ".."}
            for segment in checked_path[1:].split("/") if checked_path
        )
    ):
        _fail("URL bases require unreserved path segments")
    if value != f"{parsed.scheme}://{authority}{path}":
        _fail("URL is not canonical")
    return value


def _read_file(value: str, limit: int, label: str) -> bytes:
    if not value or len(value) > 4096 or "\x00" in value:
        _fail(f"{label} must name a bounded regular file")
    try:
        path = Path(value)
        if not stat.S_ISREG(path.lstat().st_mode):
            _fail(f"{label} must name a regular file, not a link")
        flags = (
            os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        )
        with os.fdopen(os.open(path, flags), "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= limit:
                _fail(f"{label} file has an invalid type or size")
            data = source.read(limit + 1)
    except OSError:
        _fail(f"{label} file could not be read")
    if not 1 <= len(data) <= limit:
        _fail(f"{label} file has an invalid size")
    return data


@dataclass(frozen=True)
class Deployment:
    """Validated transport defaults; credentials are excluded from representation."""

    sut_url: str
    tenant: str | None = None
    _token: str | None = field(default=None, repr=False)
    _ca: ssl.SSLContext | None = field(default=None, repr=False)

    @classmethod
    def from_environment(cls) -> Deployment:
        url = os.environ.get("A2A_TCK_SUT_URL")
        if url is None:
            _fail("A2A_TCK_SUT_URL is required")
        url = _canonical_url(url)
        tenant = os.environ.get("A2A_TCK_TENANT")
        if tenant is not None and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}", tenant
        ):
            _fail("A2A_TCK_TENANT must be a bounded public identifier")
        token = None
        token_file = os.environ.get("A2A_TCK_BEARER_TOKEN_FILE")
        if token_file is not None:
            raw = _read_file(token_file, 4098, "bearer token")
            if raw.endswith(b"\r\n"):
                raw = raw[:-2]
            elif raw.endswith(b"\n"):
                raw = raw[:-1]
            if not 1 <= len(raw) <= 4096 or not re.fullmatch(
                rb"[A-Za-z0-9._~+/-]+=*", raw
            ):
                _fail("bearer token file must contain one ASCII token line")
            token = raw.decode("ascii")
        ca = None
        ca_file = os.environ.get("A2A_TCK_CA_FILE")
        if ca_file is not None:
            raw = _read_file(ca_file, 262144, "CA")
            if not re.fullmatch(
                rb"(?:\s*-----BEGIN CERTIFICATE-----\r?\n"
                rb"[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+",
                raw,
            ):
                _fail("CA file must contain only PEM certificates")
            try:
                ca = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ca.load_verify_locations(cadata=raw.decode("ascii"))
            except (ssl.SSLError, ValueError, UnicodeError):
                _fail("CA file contains invalid certificates")
        return cls(url, tenant, token, ca)

    @property
    def scoped_url(self) -> str:
        """Return the base URL with the explicitly selected tenant, if any."""
        return self.sut_url.rstrip("/") + (f"/{self.tenant}" if self.tenant else "")

    def default_tenant(self, method: str, path: str, body: dict | None) -> dict | None:
        """Attach only the declared default to send payloads, without mutation."""
        if (
            self.tenant is not None
            and method.upper() == "POST"
            and path in {PATH_MESSAGE_SEND, PATH_MESSAGE_STREAM}
            and body is not None
            and "tenant" not in body
        ):
            return {**body, "tenant": self.tenant}
        return body

    def guard_request(self, request: httpx.Request) -> None:
        """Prevent transport credentials from leaving the selected URL scope."""
        expected = httpx.URL(self.scoped_url)
        actual = request.url
        if (
            (actual.scheme, actual.host, actual.port)
            != (expected.scheme, expected.host, expected.port)
            or not actual.path.startswith(expected.path.rstrip("/") + "/")
        ):
            _fail("request would leave the configured origin or path scope")


def _client_factory(deployment: Deployment) -> type[HttpJsonClient]:
    class DeploymentHttpJsonClient(HttpJsonClient):
        def __init__(self, base_url: str) -> None:
            advertised = _canonical_url(base_url)
            if advertised.rstrip("/") not in {
                deployment.sut_url.rstrip("/"), deployment.scoped_url,
            }:
                _fail("advertised HTTP+JSON URL does not match the configured base")
            try:
                super().__init__(deployment.scoped_url)
            except (OSError, ValueError, ImportError):
                _fail("stock transport initialization failed")
            original = self._client
            headers = dict(original.headers)
            original.close()
            if deployment._token is not None:
                headers["Authorization"] = f"Bearer {deployment._token}"
            try:
                self._client = httpx.Client(
                    base_url=deployment.scoped_url,
                    headers=headers,
                    verify=deployment._ca if deployment._ca is not None else True,
                    timeout=httpx.Timeout(5.0, read=30.0),
                    trust_env=False,
                    follow_redirects=False,
                    event_hooks={"request": [deployment.guard_request]},
                )
            except (OSError, ValueError):
                _fail("transport configuration failed")

        def _request(
            self, method: str, path: str, *, json_body: dict | None = None,
            params: dict | None = None,
        ) -> TransportResponse:
            return super()._request(
                method, path,
                json_body=deployment.default_tenant(method, path, json_body),
                params=params,
            )

        def _request_streaming(
            self, method: str, path: str, *, json_body: dict | None = None,
        ) -> StreamingResponse:
            return super()._request_streaming(
                method, path,
                json_body=deployment.default_tenant(method, path, json_body),
            )

    return DeploymentHttpJsonClient


_deployment_key = pytest.StashKey[Deployment]()
_installed_key = pytest.StashKey[bool]()


def _configuration(config: pytest.Config) -> Deployment:
    if _deployment_key not in config.stash:
        config.stash[_deployment_key] = Deployment.from_environment()
    return config.stash[_deployment_key]


def _guard_factory(plugin) -> dict:
    root = Path(inspect.getfile(HttpJsonClient)).resolve().parents[2]
    if Path(plugin.__file__).resolve() != root / "tests" / "compatibility" / "conftest.py":
        _fail("unsupported TCK conftest location")
    mapping = getattr(plugin, "_PROTOCOL_BINDING_MAP", None)
    fixture = inspect.unwrap(getattr(plugin, "transport_clients", None))
    signatures = {
        "__init__": ("self", "base_url"),
        "_request": ("self", "method", "path", "json_body", "params"),
        "_request_streaming": ("self", "method", "path", "json_body"),
    }
    if (
        not isinstance(mapping, dict)
        or mapping.get("HTTP+JSON") != ("http_json", HttpJsonClient)
        or getattr(plugin, "HttpJsonClient", None) is not HttpJsonClient
        or not inspect.isgeneratorfunction(fixture)
        or tuple(inspect.signature(fixture).parameters) != ("request", "agent_card")
        or fixture.__globals__ is not vars(plugin)
        or HttpJsonClient.__module__ != "tck.transport.http_json_client"
        or any(
            not inspect.isfunction(getattr(HttpJsonClient, name, None))
            or tuple(inspect.signature(getattr(HttpJsonClient, name)).parameters)
            != parameters
            for name, parameters in signatures.items()
        )
        or PATH_MESSAGE_SEND != "/message:send"
        or PATH_MESSAGE_STREAM != "/message:stream"
    ):
        _fail("pinned TCK HTTP+JSON deployment factory has drifted")
    return mapping


def pytest_plugin_registered(plugin, plugin_name: str, manager) -> None:
    """Bind the known conftest factory without replacing fixtures or test hooks."""
    filename = getattr(plugin, "__file__", None)
    if filename is None or Path(filename).parts[-3:] != (
        "tests", "compatibility", "conftest.py",
    ):
        return
    config = manager.get_plugin("pytestconfig")
    if not isinstance(config, pytest.Config):
        _fail("pytest configuration is unavailable during factory registration")
    if config.stash.get(_installed_key, False):
        _fail("HTTP+JSON deployment factory was registered more than once")
    mapping = _guard_factory(plugin)
    mapping["HTTP+JSON"] = ("http_json", _client_factory(_configuration(config)))
    config.stash[_installed_key] = True


def pytest_configure(config: pytest.Config) -> None:
    deployment = _configuration(config)
    if config.getoption("sut_host", default=None) != deployment.sut_url:
        _fail("--sut-host must equal A2A_TCK_SUT_URL")


def pytest_collection_finish(session: pytest.Session) -> None:
    if not session.config.stash.get(_installed_key, False):
        _fail("pinned compatibility conftest HTTP+JSON factory was not registered")
