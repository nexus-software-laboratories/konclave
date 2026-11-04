"""Focused deployment tests, run in the locked TCK Python environment."""

import importlib.util
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

import a2a_tck_deployment as deployment


@pytest.fixture
def configured_environment(monkeypatch):
    for name in (
        "A2A_TCK_SUT_URL", "A2A_TCK_TENANT",
        "A2A_TCK_BEARER_TOKEN_FILE", "A2A_TCK_CA_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("A2A_TCK_SUT_URL", "https://agent.example.test/a2a")


def test_tenant_default_preserves_explicit_values_and_input():
    config = deployment.Deployment("https://agent.example.test", "tenant-a")
    body = {"message": {"messageId": "message-a"}}
    for path in (deployment.PATH_MESSAGE_SEND, deployment.PATH_MESSAGE_STREAM):
        result = config.default_tenant("POST", path, body)
        assert result == {**body, "tenant": "tenant-a"}
        assert "tenant" not in body
        assert result["message"] is body["message"]
        for explicit in ("tenant-b", "", None):
            supplied = {**body, "tenant": explicit}
            assert config.default_tenant("POST", path, supplied) is supplied
    assert config.default_tenant("POST", "/tasks/task-a:cancel", body) is body
    assert config.default_tenant("GET", deployment.PATH_MESSAGE_SEND, body) is body
    assert config.default_tenant("POST", deployment.PATH_MESSAGE_SEND, None) is None


def test_headers_scope_and_both_send_modes(
    configured_environment, monkeypatch, tmp_path,
):
    token_file = tmp_path / "token"
    token_file.write_text("test-only-token\n", encoding="ascii")
    monkeypatch.setenv("A2A_TCK_TENANT", "tenant-a")
    monkeypatch.setenv("A2A_TCK_BEARER_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("HTTPS_PROXY", "http://unreachable.example.test:8080")
    config = deployment.Deployment.from_environment()
    assert "test-only-token" not in repr(config)
    requests = []
    clients = []
    options = []
    real_client = httpx.Client

    def respond(request):
        requests.append(request)
        if request.url.path.endswith("message:stream"):
            return httpx.Response(
                200, headers={"Content-Type": "text/event-stream"},
                content=b'data: {"task":{"id":"task-a"}}\n\n',
            )
        return httpx.Response(200, json={"task": {"id": "task-a"}})

    def make_client(*args, **kwargs):
        options.append(kwargs.copy())
        kwargs["transport"] = httpx.MockTransport(respond)
        result = real_client(*args, **kwargs)
        clients.append(result)
        return result

    monkeypatch.setattr(httpx, "Client", make_client)
    factory = deployment._client_factory(config)
    with pytest.raises(deployment.DeploymentError, match="configured base"):
        factory("https://other.example.test/a2a")
    client = factory(config.sut_url)
    try:
        assert clients[0].is_closed
        assert options[-1]["trust_env"] is False
        assert options[-1]["follow_redirects"] is False
        assert options[-1]["verify"] is True
        message = {"messageId": "message-a", "role": "user", "parts": []}
        client.send_message(message)
        streamed = client.send_streaming_message(message)
        streamed.raw_response.close()
        assert len(requests) == 2
        for request in requests:
            assert request.url.host == "agent.example.test"
            assert request.url.path.startswith("/a2a/tenant-a/message:")
            assert request.headers["Authorization"] == "Bearer test-only-token"
            assert request.headers["A2A-Version"] == "1.0"
            assert json.loads(request.content)["tenant"] == "tenant-a"
        with pytest.raises(deployment.DeploymentError, match="origin or path"):
            client._client.get("https://other.example.test/a2a/tenant-a/tasks")
        with pytest.raises(deployment.DeploymentError, match="origin or path"):
            client._client.get("https://agent.example.test/outside")
        assert len(requests) == 2
        assert "tenant" not in message
    finally:
        client.close()


def test_registration_changes_only_the_known_http_json_factory(
    configured_environment, request,
):
    root = Path(inspect.getfile(deployment.HttpJsonClient)).resolve().parents[2]
    source = root / "tests" / "compatibility" / "conftest.py"
    spec = importlib.util.spec_from_file_location("a2a_tck_fixture_probe", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original_fixture = module.transport_clients
    before = module._PROTOCOL_BINDING_MAP.copy()
    manager = SimpleNamespace(get_plugin=lambda name: request.config)
    deployment.pytest_plugin_registered(module, str(source), manager)
    assert module.transport_clients is original_fixture
    assert module.HttpJsonClient is deployment.HttpJsonClient
    for binding, entry in before.items():
        if binding != "HTTP+JSON":
            assert module._PROTOCOL_BINDING_MAP[binding] is entry
    name, factory = module._PROTOCOL_BINDING_MAP["HTTP+JSON"]
    assert name == "http_json"
    assert issubclass(factory, deployment.HttpJsonClient)
    with pytest.raises(deployment.DeploymentError, match="drifted"):
        deployment._guard_factory(module)


def test_anonymous_deployment_has_no_implicit_tenant_or_credentials(
    configured_environment,
):
    config = deployment.Deployment.from_environment()
    assert config.scoped_url == config.sut_url
    assert config.tenant is None
    assert config._token is None
    assert config._ca is None
    body = {"message": {}}
    assert config.default_tenant("POST", deployment.PATH_MESSAGE_SEND, body) is body


def test_real_pytest_collection_registers_the_deployment_factory(
    configured_environment,
):
    root = Path(inspect.getfile(deployment.HttpJsonClient)).resolve().parents[2]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).parent)
    environment.pop("PYTEST_ADDOPTS", None)
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "tests/compatibility/",
            "--collect-only", "--transport=http_json",
            "--sut-host=" + environment["A2A_TCK_SUT_URL"],
            "-p", "a2a_tck_deployment", "-q",
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_sut_url_is_required(configured_environment, monkeypatch):
    monkeypatch.delenv("A2A_TCK_SUT_URL")
    with pytest.raises(deployment.DeploymentError, match="SUT_URL is required"):
        deployment.Deployment.from_environment()


@pytest.mark.parametrize("url", [
    "http://agent.example.test", "https://user:secret@agent.example.test",
    "https://agent.example.test?query", "https://agent.example.test#fragment",
    "https://agent.example.test\\other", "https://agent.example.test/%2e%2e",
    "https://agent.example.test/../other", "https://agent.example.test//other",
    "https://AGENT.example.test", "https://agent.example.test:443",
    "http://127.1:9999", "https://agent.example.test\n",
])
def test_rejects_unsafe_urls(configured_environment, monkeypatch, url):
    monkeypatch.setenv("A2A_TCK_SUT_URL", url)
    with pytest.raises(deployment.DeploymentError):
        deployment.Deployment.from_environment()


@pytest.mark.parametrize("name,value", [
    ("A2A_TCK_TENANT", "../other"),
    ("A2A_TCK_TENANT", ""),
    ("A2A_TCK_TENANT", "x" * 129),
    ("A2A_TCK_BEARER_TOKEN_FILE", ""),
    ("A2A_TCK_CA_FILE", ""),
])
def test_rejects_unsafe_options(configured_environment, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(deployment.DeploymentError):
        deployment.Deployment.from_environment()


@pytest.mark.parametrize("content", [
    b"token\nsecond-line", b" leading-space-secret-sentinel", b"token\r", b"x" * 4097, b"",
])
def test_rejects_invalid_token_files(
    configured_environment, monkeypatch, tmp_path, content,
):
    token_file = tmp_path / "token"
    token_file.write_bytes(content)
    monkeypatch.setenv("A2A_TCK_BEARER_TOKEN_FILE", str(token_file))
    with pytest.raises(deployment.DeploymentError) as failure:
        deployment.Deployment.from_environment()
    assert content.decode("ascii") not in str(failure.value) or not content


def test_rejects_private_key_ca(configured_environment, monkeypatch, tmp_path):
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text(
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        encoding="ascii",
    )
    monkeypatch.setenv("A2A_TCK_CA_FILE", str(ca_file))
    with pytest.raises(deployment.DeploymentError, match="only PEM certificates"):
        deployment.Deployment.from_environment()


def test_canonical_card_root_slash_preserves_the_configured_tenant_scope(
    configured_environment, monkeypatch,
):
    monkeypatch.setenv("A2A_TCK_SUT_URL", "https://agent.example.test/")
    monkeypatch.setenv("A2A_TCK_TENANT", "tenant.a~b")
    config = deployment.Deployment.from_environment()
    assert config.scoped_url == "https://agent.example.test/tenant.a~b"
    client = deployment._client_factory(config)("https://agent.example.test/")
    try:
        assert str(client._client.base_url) == "https://agent.example.test/tenant.a~b/"
    finally:
        client.close()
