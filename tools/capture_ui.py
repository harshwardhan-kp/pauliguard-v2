"""Repeatable UI screenshot for the deck. Run with the API server up on :8077.

    .venv/bin/python -m uvicorn pauliguard.api:app --port 8077 &
    .venv/bin/python tools/capture_ui.py
"""
import sys, pathlib
from playwright.sync_api import sync_playwright

OUT = pathlib.Path("docs/screenshots"); OUT.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1680, "height": 1010}, device_scale_factor=2)
    pg.goto("http://localhost:8077/", wait_until="networkidle")
    pg.get_by_role("button", name="RUN BOTH", exact=False).click()
    pg.wait_for_function(
        "() => document.body.innerText.includes('MESSAGE CHANGED') "
        "&& document.body.innerText.includes('MALLEABILITY DETECTED')",
        timeout=90_000)
    pg.wait_for_timeout(1200)
    pg.screenshot(path=str(OUT / "pauliguard-ui.png"))
    print("wrote", OUT / "pauliguard-ui.png")
    b.close()
