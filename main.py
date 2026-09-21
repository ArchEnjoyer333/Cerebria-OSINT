from pathlib import Path
import sys
import traceback
from typing import Any, Dict

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from modules import REGISTRY

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.toml"
INDEX_PATH = BASE_DIR / "index.html"
LOGO_PATH = BASE_DIR / "logo.svg"
STATIC_DIR = BASE_DIR / "static"

DEFAULT_CONFIG_CONTENT = """[app]
name = "Cerebria"
version = "v0.1.0"
status = "Beta"
tab_title = "Cerebria — OSINT Framework"

[server]
host = "127.0.0.1"
port = 3000
debug = false

[welcome]
title = "Welcome to Cerebria."
subtitle = "Select an intelligence module from the sidebar to start your investigation."
icon = "/logo.svg"
accent_word = "Cerebria."

[links]
github = "https://github.com"
docs = "https://github.com"

[theme]
bg_main = "#050505"
bg_sidebar = "#0a0a0a"
bg_card = "#111111"
grid_size = "48px"
grid_opacity = "0.03"

[modules_config.ipwhois]
enabled = true
name = "IP Whois"
description = "Autonomous system, network routing, and deep geolocation lookup"

[modules_config.phone_hlr]
enabled = true
name = "Phone HLR"
description = "Cellular carrier detection, international standard mapping & line validation"

[modules_config.subdomains]
enabled = true
name = "Subdomains"
description = "Passive subdomain enumeration via Certificate Transparency logs"

[modules_config.vpn_detector]
enabled = true
name = "VPN & Proxy"
description = "Detects commercial VPNs, Proxies, and Datacenter IPs"

[modules_config.port_scanner]
enabled = true
name = "Port Scanner"
description = "High-performance asynchronous TCP scanning of Top-20 critical ports"
"""


def ensure_config_exists() -> None:
    if not CONFIG_PATH.exists():
        try:
            CONFIG_PATH.write_text(DEFAULT_CONFIG_CONTENT, encoding="utf-8")
            print(f"[*] Generated default configuration at {CONFIG_PATH}")
        except Exception as e:
            print(f"[!] Warning: Could not write default config.toml: {e}")


def load_config() -> Dict[str, Any]:
    ensure_config_exists()
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            print(f"[!] Warning: Failed to parse config.toml: {e}")
    return {}


app = FastAPI(title="Cerebria OSINT Core")

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    if not INDEX_PATH.exists():
        return HTMLResponse(
            status_code=404,
            content=f"<h3>index.html not found in {BASE_DIR}</h3>",
        )
    return HTMLResponse(content=INDEX_PATH.read_text(encoding="utf-8"))


@app.get("/logo.svg")
async def serve_logo():
    if not LOGO_PATH.exists():
        return JSONResponse(
            status_code=404,
            content={"status": "error", "error": "logo.svg not found"},
        )
    return FileResponse(LOGO_PATH, media_type="image/svg+xml")


@app.get("/api/config")
async def get_config():
    cfg = load_config()
    mod_configs = cfg.get("modules_config", {})

    modules_payload = []
    for mod_id, module in REGISTRY.items():
        override = mod_configs.get(mod_id, {})
        is_enabled = override.get("enabled", True)
        modules_payload.append(module.get_info(enabled=is_enabled, override=override))

    return JSONResponse(
        content={
            "app": cfg.get("app", {"name": "Cerebria", "version": "v0.1.0", "status": "Beta"}),
            "server": cfg.get("server", {"host": "127.0.0.1", "port": 3000}),
            "welcome": cfg.get("welcome", {}),
            "links": cfg.get("links", {}),
            "theme": cfg.get("theme", {}),
            "modules": modules_payload,
        }
    )


@app.get("/api/scan")
async def execute_scan(
    module_id: str = Query(..., description="Module ID from REGISTRY"),
    target: str = Query(..., description="Target host, IP, or query"),
):
    module = REGISTRY.get(module_id)
    if not module:
        return JSONResponse(
            status_code=404,
            content={"status": "error", "error": f"Module '{module_id}' is not registered"},
        )

    is_valid, err_msg = module.validate_target(target)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "error": err_msg},
        )

    try:
        cfg = load_config().get("modules_config", {}).get(module_id, {})
        result = await module.run(target, cfg)
        return JSONResponse(content={"status": "OK", **result})
    except Exception as e:
        traceback.print_exc()
        error_detail = str(e) if str(e) else repr(e)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "error": f"Execution error: {error_detail}"},
        )


if __name__ == "__main__":
    import uvicorn

    ensure_config_exists()
    cfg = load_config()
    server_cfg = cfg.get("server", {})
    host = server_cfg.get("host", "127.0.0.1")
    port = int(server_cfg.get("port", 3000))

    print(f"[*] Cerebria Core starting on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
