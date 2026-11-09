from __future__ import annotations

import asyncio
import socket

import httpx
import segno
import uvicorn

from .config import Settings
from .hook_api import create_hook_router
from .phone import create_phone_app
from .proxy import create_proxy_app
from .scan_index import ScanIndex
from .scanner import Scanner
from .store import Store
from .worst_case import warm_up

WARM_UP_TIMEOUT_SECONDS = 60.0


def lan_address() -> str:
    """Find the outbound interface address; the UDP connect sends no packets."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
        except OSError:
            return "127.0.0.1"


async def serve(settings: Settings, store: Store, log_level: str = "warning") -> None:
    """Run proxy and phone apps on one event loop, as `Store` requires."""
    index = ScanIndex(settings.index_path) if settings.index_path else None
    scanner = Scanner(settings, index) if index else None
    if scanner:
        scanner.start()
    proxy_app = create_proxy_app(settings, store)
    proxy_app.include_router(create_hook_router(settings, store, index=index, scanner=scanner))
    proxy = uvicorn.Server(uvicorn.Config(
        proxy_app, host="127.0.0.1", port=settings.proxy_port, log_level=log_level,
    ))
    phone = uvicorn.Server(uvicorn.Config(
        create_phone_app(settings, store, scanner), host="0.0.0.0", port=settings.phone_port, log_level=log_level,
    ))
    async with httpx.AsyncClient(timeout=WARM_UP_TIMEOUT_SECONDS) as client:
        await asyncio.gather(proxy.serve(), phone.serve(), warm_up(settings, client))


def main() -> None:
    settings = Settings.from_env()
    phone_url = f"http://{lan_address()}:{settings.phone_port}/?t={settings.phone_token}"
    print(f"Point your agent at:  http://127.0.0.1:{settings.proxy_port}/v1")
    print(f"Open on your phone:   {phone_url}")
    print(f"Live dashboard:       http://127.0.0.1:{settings.phone_port}/dash?t={settings.phone_token}\n")
    segno.make(phone_url).terminal(compact=True)
    asyncio.run(serve(settings, Store(settings)))


if __name__ == "__main__":
    main()
