from __future__ import annotations

from pathlib import Path
import json
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

def run(out_dir: Path, host: str, port: int):
    app = FastAPI()
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (static_dir / "index.html").read_text(encoding="utf-8")

    @app.get("/graph.json")
    def graph():
        return JSONResponse(json.loads((out_dir / "graph.json").read_text(encoding="utf-8")))

    @app.get("/report.json")
    def report():
        p = out_dir / "report.json"
        if not p.exists():
            return JSONResponse({"error": "report.json not found"}, status_code=404)
        return JSONResponse(json.loads(p.read_text(encoding="utf-8")))

    uvicorn.run(app, host=host, port=port)
