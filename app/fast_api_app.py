# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import ipaddress
import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable

from a2a.server.tasks import InMemoryTaskStore
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.runners import Runner

from app.app_utils import services
from app.app_utils.a2a import attach_a2a_routes

logger = logging.getLogger(__name__)

load_dotenv()
allow_origins = (
    os.getenv("ALLOW_ORIGINS", "").split(",") if os.getenv("ALLOW_ORIGINS") else None
)
otel_to_cloud = True

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_allowed_cidrs(raw_cidrs: str | None) -> list[IPNetwork]:
    """Parse comma-separated CIDR blocks or IP addresses from ALLOWED_CIDRS."""
    if not raw_cidrs:
        return []
    networks: list[IPNetwork] = []
    for entry in raw_cidrs.split(","):
        cidr = entry.strip()
        if not cidr:
            continue
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid CIDR entry in ALLOWED_CIDRS: %s", cidr)
    return networks


def extract_client_ip(request: Request) -> str | None:
    """Extract client IP from X-Forwarded-For, X-Real-IP, or request.client."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first_ip = xff.split(",")[0].strip()
        if first_ip:
            return first_ip
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip and x_real_ip.strip():
        return x_real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return None


def is_ip_allowed(client_ip: str | None, networks: list[IPNetwork]) -> bool:
    """Return True if no CIDR restriction is configured or client_ip matches an allowed CIDR."""
    if not networks:
        return True
    if not client_ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return False
    if any(ip_obj in net for net in networks):
        return True
    ipv4_mapped = getattr(ip_obj, "ipv4_mapped", None)
    if ipv4_mapped is not None and any(ipv4_mapped in net for net in networks):
        return True
    return False


allowed_cidrs: list[IPNetwork] = parse_allowed_cidrs(os.getenv("ALLOWED_CIDRS"))

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    from app.agent import app as adk_app
    from app.agent import root_agent

    runner = Runner(
        app=adk_app,
        session_service=services.get_session_service(),
        artifact_service=services.get_artifact_service(),
        auto_create_session=True,
    )
    app.state.runner = runner
    app.state.agent_app_name = adk_app.name
    await attach_a2a_routes(
        app,
        agent=root_agent,
        runner=runner,
        task_store=InMemoryTaskStore(),
        rpc_path=f"/a2a/{adk_app.name}",
    )
    yield


app: FastAPI = get_fast_api_app(
    agents_dir=AGENT_DIR,
    web=True,
    artifact_service_uri=services.ARTIFACT_SERVICE_URI,
    allow_origins=allow_origins,
    session_service_uri=services.SESSION_SERVICE_URI,
    otel_to_cloud=otel_to_cloud,
    lifespan=lifespan,
)
app.title = "k8s-inv-agent"
app.description = "API for interacting with the Agent k8s-inv-agent"


@app.middleware("http")
async def cidr_allowlist_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Enforce ingress IP allowlisting configured via ALLOWED_CIDRS."""
    raw_env_cidrs = os.getenv("ALLOWED_CIDRS")
    active_cidrs = (
        parse_allowed_cidrs(raw_env_cidrs)
        if raw_env_cidrs is not None
        else allowed_cidrs
    )
    if active_cidrs:
        client_ip = extract_client_ip(request)
        if not is_ip_allowed(client_ip, active_cidrs):
            logger.warning(
                "Blocked request from unauthorized IP %s to %s",
                client_ip,
                request.url.path,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": (
                        f"Forbidden: client IP '{client_ip or 'unknown'}' "
                        "is not in ALLOWED_CIDRS."
                    )
                },
            )
    return await call_next(request)


# Main execution
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
