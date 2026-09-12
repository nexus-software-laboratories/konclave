from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import httpx
from a2a.client import Client, ClientConfig, create_client
from a2a.client.client_factory import TransportProtocol
from a2a.types import (
    GetTaskRequest,
    ListTasksRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    StreamResponse,
    TaskState,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sut-url", required=True)
    return parser.parse_args()


def require_loopback_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("the SDK interoperability SUT must be an HTTP loopback URL")
    return value.rstrip("/")


async def collect(events: AsyncIterator[StreamResponse]) -> list[StreamResponse]:
    return [event async for event in events]


def require_completed_task(response: StreamResponse) -> None:
    if not response.HasField("task"):
        raise RuntimeError("a2a-python did not decode a Task response")
    if response.task.status.state != TaskState.TASK_STATE_COMPLETED:
        raise RuntimeError("a2a-python decoded a non-terminal task")
    if not response.task.status.HasField("timestamp"):
        raise RuntimeError("a2a-python decoded a task without a status timestamp")
    if not response.task.status.timestamp.ToJsonString().endswith("Z"):
        raise RuntimeError("a2a-python decoded a non-canonical UTC timestamp")


async def create_http_json_client(sut_url: str, streaming: bool) -> Client:
    http_client = httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(10.0),
        trust_env=False,
    )
    config = ClientConfig(
        streaming=streaming,
        httpx_client=http_client,
        supported_protocol_bindings=[TransportProtocol.HTTP_JSON],
        accepted_output_modes=["text/plain"],
    )
    try:
        client = await create_client(sut_url, config)
    except Exception:
        await http_client.aclose()
        raise
    return client


async def run(sut_url: str) -> None:
    client = await create_http_json_client(sut_url, streaming=False)
    try:
        request = SendMessageRequest(
            message=Message(
                message_id="tck-artifact-text-sdk-interop",
                role=Role.ROLE_USER,
                parts=[Part(text="SDK interoperability request")],
            ),
            configuration=SendMessageConfiguration(history_length=1),
        )
        responses = await collect(client.send_message(request))
        if len(responses) != 1:
            raise RuntimeError("a2a-python returned an unexpected response count")
        response = responses[0]
        require_completed_task(response)
        task = response.task
        if (
            len(task.artifacts) != 1
            or len(task.artifacts[0].parts) != 1
            or task.artifacts[0].parts[0].text != "Generated text content"
            or task.artifacts[0].parts[0].media_type != "text/plain"
        ):
            raise RuntimeError("a2a-python did not decode the canonical text artifact")

        fetched = await client.get_task(GetTaskRequest(id=task.id, history_length=1))
        if (
            fetched.id != task.id
            or fetched.context_id != task.context_id
            or fetched.status.state != TaskState.TASK_STATE_COMPLETED
        ):
            raise RuntimeError("a2a-python GetTask did not preserve task identity")

        page = await client.list_tasks(ListTasksRequest(page_size=10))
        if not any(listed.id == task.id for listed in page.tasks):
            raise RuntimeError("a2a-python ListTasks omitted the created task")
    finally:
        await client.close()

    client = await create_http_json_client(sut_url, streaming=True)
    try:
        events = await collect(
            client.send_message(
                SendMessageRequest(
                    message=Message(
                        message_id="sdk-stream-interop",
                        role=Role.ROLE_USER,
                        parts=[Part(text="SDK streaming interoperability request")],
                    )
                )
            )
        )
        if len(events) != 1:
            raise RuntimeError("a2a-python decoded an unexpected SSE event count")
        require_completed_task(events[0])
    finally:
        await client.close()


def main() -> None:
    args = parse_args()
    asyncio.run(run(require_loopback_url(args.sut_url)))
    print("a2a-python v1.0.3 interoperability passed.")


if __name__ == "__main__":
    main()
