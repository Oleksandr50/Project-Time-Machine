from __future__ import annotations

from datetime import datetime
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
from . import db
from . import services
from .analyzer import tail_text_file, sqlite_info

@asynccontextmanager
async def lifespan(app):
    from .jobs import Runner
    from .lifecycle import guard
    with guard(projects.base_settings.data_dir):
        runner=Runner()
        runner.start()
        try:yield
        finally:runner.close()


app = FastAPI(title="Project Time Machine",docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)

app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")

from .ui import templates
from . import i18n


from . import projects
from . import security
from .migrations import MigrationError
import sqlite3


from .access import gate
app.middleware('http')(gate)
from .auth_routes import router as auth_router
app.include_router(auth_router)
from .ui_routes import router as ui_router
app.include_router(ui_router)
from .backup_routes import router as backup_router
app.include_router(backup_router)
from .restore_routes import router as restore_router
app.include_router(restore_router)


@app.post('/projects/add')
def project_add(request: Request, path: str = Form(...), name: str = Form(default=""), description: str = Form(default=""), category: str = Form(default="other"), csrf_token: str = Form(default="")):
    security.require_management(request, csrf_token)
    try:
        pid = projects.add_project(path,name,description,category)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse('/?project_id=' + str(pid), status_code=303)


@app.post('/projects/edit')
def project_edit(request: Request, project_id: int = Form(...), name: str = Form(default=""),
                 description: str = Form(default=''), category: str = Form(default='other'),
                 exclusions: str = Form(default=''), python_analysis: str = Form(default='off'),
                 analyze_archived: str = Form(default='off'), analyze_generated: str = Form(default='off'),
                 analyze_dependencies: str = Form(default='off'), csrf_token: str = Form(default='')):
    security.require_management(request,csrf_token)
    try:
        projects.update_project(project_id,name,description,category,
            [r.strip() for r in exclusions.splitlines() if r.strip()],
            {'python_analysis':python_analysis=='on','analyze_archived':analyze_archived=='on',
             'analyze_generated':analyze_generated=='on','analyze_dependencies':analyze_dependencies=='on'})
    except ValueError as exc: raise HTTPException(400,str(exc))
    return RedirectResponse('/?project_id='+str(project_id),status_code=303)


@app.post('/projects/remove')
def project_remove(request: Request, project_id: int = Form(...), csrf_token: str = Form(default="")):
    security.require_management(request, csrf_token)
    try:
        projects.remove_project(project_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    remaining = projects.list_projects()
    response = RedirectResponse('/?project_id=' + str(remaining[0]['id']) if remaining else '/', status_code=303)
    response.delete_cookie('ptm_active_project')
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # Render user-friendly HTML for browser pages; return plain text for API callers.
    accept = (request.headers.get("accept") or "").lower()
    wants_html = "text/html" in accept or "*/*" in accept or accept == ""

    if wants_html and request.url.path.startswith(("/", "/files", "/file", "/logs", "/logs/view", "/compare", "/timeline", "/snapshots", "/functions", "/audit", "/sqlite", "/backups", "/report")):
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            status_code=exc.status_code,
            context={
                "request": request,
                "title": f"Ошибка {exc.status_code}",
                "status_code": exc.status_code,
                "detail": i18n.message(exc.detail),
                "title_key": "error.title",
                "path": request.url.path,
                "now": datetime.now().isoformat(timespec='seconds'),
            },
        )

    return PlainTextResponse(i18n.message(exc.detail), status_code=exc.status_code)


def fmt_bytes(n: int) -> str:
    x = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if x < 1024:
            return f"{x:.1f} {unit}" if unit != "B" else f"{int(x)} B"
        x /= 1024
    return f"{x:.1f} PB"


def has_env_file():
    from .filesystem import open_project_file
    try:
        with open_project_file(settings.agent_root,'.env',settings): return True
    except FileNotFoundError: return False
    except (OSError,ValueError): return None


def current_status() -> dict:
    services.ensure_db()
    with db.db_conn() as conn:
        latest = conn.execute("SELECT * FROM snapshots WHERE backup_point_id IS NULL ORDER BY id DESC LIMIT 1").fetchone()
        last_backup = conn.execute("SELECT * FROM backups ORDER BY id DESC LIMIT 1").fetchone()

        if latest:
            audit = services.audit_summary(conn, int(latest["id"]))
            report_path = str(settings.reports_dir / "current_state.md") if (settings.reports_dir / "current_state.md").exists() else None
            return {
                "agent_root": str(settings.agent_root),
                "snapshot_id": int(latest["id"]),
                "category_metrics": __import__("json").loads(latest["category_metrics"]),
                "last_analysis": latest["created_at"],
                "last_backup": last_backup["created_at"] if last_backup else None,
                "total_files": latest["total_files"],
                "python_files": latest["python_files"],
                "functions_count": latest["functions_count"],
                "classes_count": latest["classes_count"],
                "sqlite_files": latest["sqlite_files"],
                "log_files": latest["log_files"],
                "total_bytes_human": fmt_bytes(latest["total_bytes"]),
                "baseline_digest": latest["baseline_digest"],
                "changes_from_prev": latest["changes_from_prev"],
                "last_mtime_human": str(datetime.fromtimestamp(int(latest["last_mtime"]))) if latest["last_mtime"] else None,
                "has_env": has_env_file(),
                "audit": audit,
                "report_path": report_path,
                "error": None if settings.agent_root.is_dir() else i18n.message("Каталог проекта недоступен"),
            }

        # no snapshots
        return {
            "agent_root": str(settings.agent_root),
            "snapshot_id": None,
            "last_analysis": None,
            "last_backup": last_backup["created_at"] if last_backup else None,
            "total_files": 0,
            "python_files": 0,
            "functions_count": 0,
            "classes_count": 0,
            "sqlite_files": 0,
            "log_files": 0,
            "total_bytes_human": "—",
            "baseline_digest": None,
            "changes_from_prev": None,
            "last_mtime_human": None,
            "has_env": has_env_file(),
            "audit": {"critical": 0, "high": 0, "medium": 0, "info": 0},
            "report_path": None,
            "error": None if settings.agent_root.is_dir() else i18n.message("Каталог проекта недоступен"),
        }


























@app.get("/backups/download")
def backups_download(id: int):
    services.ensure_db()
    with db.db_conn() as conn:
        r = conn.execute("SELECT * FROM backups WHERE id=?", (id,)).fetchone()
        if not r:
            raise HTTPException(404, "Backup не найден")
        p = Path(r["archive_path"])
        if not p.exists():
            raise HTTPException(404, "Файл архива отсутствует")

    from .archives import open_archive, availability
    state=availability(p)
    if state=='Missing': raise HTTPException(404,'Архив отсутствует (Missing)')
    if state!='Available': raise HTTPException(403,'Архив недоступен в настроенном хранилище')
    from . import backups
    with db.db_conn() as conn:
        engine=conn.execute('SELECT id FROM backup_points WHERE backup_id=?',(id,)).fetchone()
    if engine:
        # Pin a verified file descriptor before HTTP headers; no corrupt package gets a 200.
        from .backup_storage import project_lock,capacity,digest_stream
        with project_lock(settings.project_id),capacity():
            backups.verify_unlocked(engine[0])
            handle=open_archive(p);stream=handle.__enter__()
            try:
                if digest_stream(stream)[0]!=r['sha256']:raise ValueError('engine.corrupt')
                stream.seek(0)
            except Exception:
                handle.__exit__(None,None,None);raise
        from starlette.background import BackgroundTask
        def verified_chunks():
            try:
                for chunk in iter(lambda:stream.read(1024*1024),b''):yield chunk
            finally:handle.__exit__(None,None,None)
        return StreamingResponse(verified_chunks(),media_type='application/octet-stream',
                                 headers={'Content-Disposition':'attachment; filename="'+engine[0]+'.ptm"'},
                                 background=BackgroundTask(handle.__exit__,None,None,None))
    def chunks():
        with open_archive(p) as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''): yield chunk
    return StreamingResponse(chunks(),media_type='application/gzip')




@app.post("/actions/analyze")
def action_analyze(description: str = Form(default="")):
    try:
        projects.validate_path(str(settings.agent_root))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    services.run_analysis(description=description)
    return RedirectResponse(url="/?project_id="+str(settings.project_id), status_code=303)


@app.post("/actions/backup")
def action_backup(request:Request,kind:str=Form(default='full'),description:str=Form(default='')):
    try:
        projects.validate_path(str(settings.agent_root))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    from . import jobs
    jobs.enqueue(settings.project_id,request.state.user['user_id'],kind=kind,description=description)
    return RedirectResponse(url="/backups?project_id="+str(settings.project_id), status_code=303)


@app.get("/api/status")
def api_status():
    return current_status()


from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def invalid_form(request,exc):
    from .responses import error_response
    return error_response(request,422,'error.validation')
