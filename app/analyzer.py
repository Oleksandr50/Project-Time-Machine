from __future__ import annotations

import ast
import hashlib
import os
import re
import sqlite3
import tarfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .config import settings


@dataclass
class FileInfo:
    path: str
    size: int
    mtime: int
    sha256: str | None
    file_type: str
    lines: int | None
    is_secret: bool
    file_category: str = "active"


@dataclass
class Entity:
    path: str
    kind: str
    name: str
    qualname: str | None
    lineno: int | None
    end_lineno: int | None
    signature: str | None
    docstring: str | None
    decorators: list[str]
    imports: list[str]
    calls: list[str]
    risk_level: str
    risk_reasons: list[str]
    analyzer_id: str = "python"


@dataclass
class SnapshotResult:
    created_at: str
    description: str
    total_files: int
    python_files: int
    total_bytes: int
    functions_count: int
    classes_count: int
    sqlite_files: int
    log_files: int
    last_mtime: int
    baseline_digest: str
    files: list[FileInfo]
    entities: list[Entity]
    audit: list[dict[str, Any]]
    analysis_info: dict = field(default_factory=dict)


TEXT_EXT = {
    ".py",
    ".md",
    ".txt",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".cs", ".html", ".css", ".xml", ".sql", ".sh", ".ps1",
}

LOG_EXT = {".log"}
SQLITE_EXT = {".sqlite", ".sqlite3", ".db"}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def is_secret_path(rel_path: str) -> bool:
    name = Path(rel_path).name
    if name.startswith(".env") or any(x in Path(rel_path).parts for x in (".ssh", ".aws", ".gnupg")):
        return True
    if name in settings.secret_file_names:
        return True
    lower = rel_path.lower()
    # keep heuristic conservative: only if it contains these AND file looks like config
    for s in settings.secret_path_substrings:
        if s in lower and (lower.endswith('.json') or lower.endswith('.yml') or lower.endswith('.yaml') or lower.endswith('.ini') or lower.endswith('.toml') or lower.endswith('.cfg') or lower.endswith('.env') or lower.endswith('.txt')):
            return True
    return False


def file_type_for(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".py":
        return "python"
    if ext in SQLITE_EXT:
        return "sqlite"
    if ext in LOG_EXT:
        return "log"
    if ext in TEXT_EXT:
        return "text"
    return "binary"


def sha256_file(path: Path, max_bytes: int | None = None) -> str | None:
    h=hashlib.sha256()
    try:
        with open_source(path) as stream:
            before=os.fstat(stream.fileno())
            if max_bytes is not None and before.st_size>max_bytes: return None
            for chunk in iter(lambda:stream.read(1024*1024),b''): h.update(chunk)
            after=os.fstat(stream.fileno())
            if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
                raise ValueError('Файл изменился во время чтения; повторите анализ')
    except FileNotFoundError: return None
    return h.hexdigest()


def count_lines_text(path: Path, limit_bytes: int = 8*1024*1024):
    with open_source(path) as stream:
        if os.fstat(stream.fileno()).st_size>limit_bytes: return None
        data=stream.read(limit_bytes+1)
    if len(data)>limit_bytes: return None
    return data.count(b'\n')+(1 if data and not data.endswith(b'\n') else 0)


from .scanner import iter_files, open_source, read_text, eligible_analysis, category


def compute_project_digest(file_infos: list[FileInfo]) -> str:
    acc = hashlib.sha256()
    for fi in sorted(file_infos, key=lambda x: x.path):
        if fi.sha256:
            acc.update(fi.path.encode() + b"\0" + bytes.fromhex(fi.sha256))
    return acc.hexdigest()


# ----------------- Python static analysis -----------------

DANGEROUS_CALL_PATTERNS = {
    "subprocess.run": "subprocess",
    "subprocess.Popen": "subprocess",
    "os.system": "os.system",
    "os._exit": "os._exit",
    "sys.exit": "sys.exit",
    "requests.post": "http_post",
    "httpx.post": "http_post",
    "aiohttp.ClientSession.post": "http_post",
    "requests.get": "http_get",
    "httpx.get": "http_get",
    "open": "file_io",
    "Path.write_text": "file_write",
    "Path.write_bytes": "file_write",
    "sqlite3.connect": "sqlite",
}

HIGH_RISK_KEYWORDS = [
    "telegram",
    "homeassistant",
    "mqtt",
    "qdrant",
    "postgres",
    "drop table",
    "delete from",
    "insert into",
    "update ",
    "token",
    "api_key",
    "apikey",
    "password",
    "secret",
]


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return None


class PyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[str] = []
        self.calls: list[str] = []
        self.str_consts: list[str] = []

    def visit_Import(self, node: ast.Import) -> Any:
        for n in node.names:
            self.imports.append(n.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        mod = node.module or ""
        for n in node.names:
            if mod:
                self.imports.append(f"{mod}.{n.name}")
            else:
                self.imports.append(n.name)

    def visit_Call(self, node: ast.Call) -> Any:
        dn = dotted_name(node.func)
        if dn:
            self.calls.append(dn)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, str):
            s = node.value.strip()
            if s:
                self.str_consts.append(s)


def safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = node.args

    def fmt_arg(a: ast.arg, default: ast.expr | None = None) -> str:
        s = a.arg
        if a.annotation:
            s += f": {safe_unparse(a.annotation)}"
        if default is not None:
            s += f"={safe_unparse(default)}"
        return s

    parts: list[str] = []

    pos = list(args.posonlyargs) + list(args.args)
    defaults = list(args.defaults)
    # align defaults with last N positional
    dmap: dict[int, ast.expr] = {}
    if defaults:
        for i, d in enumerate(defaults):
            dmap[len(pos) - len(defaults) + i] = d

    for i, a in enumerate(args.posonlyargs):
        parts.append(fmt_arg(a, dmap.get(i)))
    if args.posonlyargs:
        parts.append("/")

    base_index = len(args.posonlyargs)
    for j, a in enumerate(args.args):
        idx = base_index + j
        parts.append(fmt_arg(a, dmap.get(idx)))

    if args.vararg:
        parts.append("*" + fmt_arg(args.vararg))
    elif args.kwonlyargs:
        parts.append("*")

    for k, a in enumerate(args.kwonlyargs):
        default = args.kw_defaults[k] if args.kw_defaults else None
        parts.append(fmt_arg(a, default))

    if args.kwarg:
        parts.append("**" + fmt_arg(args.kwarg))

    ret = ""
    if node.returns:
        ret = f" -> {safe_unparse(node.returns)}"

    return f"({', '.join(parts)}){ret}"


def risk_for_entity(entity_calls: list[str], entity_imports: list[str], strings: list[str]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    risk = "safe"

    joined = "\n".join(strings).lower()

    def bump(level: str) -> None:
        nonlocal risk
        order = {"safe": 0, "warn": 1, "high": 2}
        if order[level] > order[risk]:
            risk = level

    for c in entity_calls:
        for pat, why in DANGEROUS_CALL_PATTERNS.items():
            # suffix match to catch aliased modules partially
            if c == pat or c.endswith("." + pat.split(".")[-1]) and (pat.split(".")[0] in c):
                if why in ("os._exit", "sys.exit", "os.system", "subprocess", "http_post"):
                    bump("high")
                else:
                    bump("warn")
                reasons.append(f"вызов: {c} ({why})")

    imp_low = [i.lower() for i in entity_imports]
    for kw in ["requests", "httpx", "aiohttp", "subprocess", "telebot", "telegram", "paho.mqtt", "homeassistant"]:
        if any(kw in i for i in imp_low):
            bump("warn")
            reasons.append(f"импорт/зависимость: {kw}")

    for kw in HIGH_RISK_KEYWORDS:
        if kw in joined:
            bump("warn")
            reasons.append(f"строки содержат: {kw}")

    # map internal levels to UI
    if risk == "safe":
        return "green", reasons
    if risk == "warn":
        return "yellow", reasons
    return "red", reasons


def analyze_python_file(path: Path, rel: str) -> tuple[list[Entity], list[dict[str, Any]]]:
    from .audit_rules import finding, inspect_tree
    from .redaction import redact
    try:
        with open_source(path) as stream:raw=stream.read(2*1024*1024+1)
        if len(raw)>2*1024*1024:return [],[finding('limit',rel)]
        source=raw.decode('utf-8',errors='replace')
        tree=ast.parse(source)
    except SyntaxError as exc:return [],[finding('syntax',rel,exc.lineno)]
    except (RecursionError,MemoryError):return [],[finding('limit',rel)]
    except (OSError,UnicodeError):return [],[finding('read',rel)]
    findings=inspect_tree(tree,rel);entities=[]
    # Each entity owns only its local calls/constants; a sibling cannot inherit its risk.
    class Local(PyVisitor):
        def __init__(self):
            super().__init__();self.lines=set()
        def generic_visit(self,node):
            if hasattr(node,'lineno'):self.lines.add(node.lineno)
            super().generic_visit(node)
        def visit_Constant(self,node):
            self.lines.add(node.lineno);super().visit_Constant(node)
        def visit_FunctionDef(self,n):pass
        def visit_AsyncFunctionDef(self,n):pass
        def visit_ClassDef(self,n):pass
    imports=PyVisitor();imports.visit(tree)
    by_line={}
    for f in findings:
        for line in f.get('occurrences',[]) or [f.get('lineno')]:by_line.setdefault(line,[]).append(f)
    def walk(node,parents=()):
        for child in ast.iter_child_nodes(node):
            if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                visitor=Local()
                for item in child.body:visitor.visit(item)
                own=list({f['fingerprint']:f for line in visitor.lines|{child.lineno} for f in by_line.get(line,[])}.values())
                risk='red' if any(f['severity'] in ('high','critical') for f in own) else ('yellow' if own else 'green')
                entities.append(Entity(path=rel,kind='class' if isinstance(child,ast.ClassDef) else ('async_function' if isinstance(child,ast.AsyncFunctionDef) else 'function'),
                    name=child.name,qualname='.'.join((*parents,child.name)),lineno=child.lineno,end_lineno=child.end_lineno,
                    signature=redact(function_signature(child)) if not isinstance(child,ast.ClassDef) else None,
                    docstring=redact(ast.get_docstring(child) or '')[:8192],decorators=[redact(safe_unparse(d))[:2048] for d in child.decorator_list],
                    imports=sorted(set(imports.imports)),calls=sorted(set(visitor.calls)),risk_level=risk,
                    risk_reasons=sorted(set(f['message'] for f in own))))
                walk(child,(*parents,child.name))
            else:walk(child,parents)
    walk(tree)
    return entities,findings


from .analysis_plugins import register, Adapter
register(Adapter('python',('.py',),analyze_python_file))


# ----------------- Snapshot creation -----------------


def create_snapshot(description: str = "", tick=lambda:None) -> SnapshotResult:
    root = settings.agent_root
    created_at = _now()

    files: list[FileInfo] = []
    entities: list[Entity] = []
    audit: list[dict[str, Any]] = []
    analysis_info={"format_version":1,"analyzers":{},"unsupported":{},"skipped":{}}

    total_files = 0
    python_files = 0
    sqlite_files = 0
    log_files = 0
    total_bytes = 0
    last_mtime = 0

    for p, st in iter_files(root):
        tick()
        rel = str(p.relative_to(root))
        total_files += 1
        total_bytes += st.st_size
        last_mtime = max(last_mtime, int(st.st_mtime))

        ftype = file_type_for(p)
        if ftype == "python":
            python_files += 1
        elif ftype == "sqlite":
            sqlite_files += 1
        elif ftype == "log":
            log_files += 1

        secret = is_secret_path(rel)

        # Hashing policy:
        # - always hash python/text up to max_hash_bytes_general
        # - hash binary only up to max_hash_bytes_general
        maxb = settings.max_hash_bytes_general
        if ftype in ("python", "text", "sqlite", "log"):
            sha = sha256_file(p, max_bytes=maxb)
        else:
            sha = sha256_file(p, max_bytes=maxb)

        lines = count_lines_text(p) if ftype in ("python", "text", "log") and not secret else None

        files.append(
            FileInfo(
                path=rel,
                size=st.st_size,
                mtime=int(st.st_mtime),
                sha256=sha,
                file_type=ftype,
                lines=lines,
                is_secret=secret,
                file_category=category(rel),
            )
        )

        from .analysis_plugins import for_path
        from .audit_rules import finding
        adapter=for_path(p)
        if not secret and eligible_analysis(rel) and (not adapter or adapter.id!='python' or settings.scan_settings.get('python_analysis',True)):
            if adapter:
                bucket=analysis_info['analyzers'].setdefault(adapter.id,{'files':0,'errors':0})
                bucket['files']+=1
                if st.st_size>2*1024*1024:
                    ents,finds=[],[finding('limit',rel)]
                else:
                    try:
                        ents,finds=adapter.analyze(p,rel)
                        if len(ents)>10000 or len(finds)>10000:raise ValueError('Adapter result limit')
                        for ent in ents:
                            if ent.path!=rel or ent.kind not in ('function','async_function','class'):raise ValueError('Adapter contract')
                            ent.analyzer_id=adapter.id
                        for f in finds:
                            if f.get('path')!=rel:raise ValueError('Adapter contract')
                            f['analyzer_id']=adapter.id
                    except Exception:
                        ents,finds=[],[finding('plugin',rel)]
                bucket['errors']+=int(any(f.get('rule_id') in ('python.syntax','python.read','python.limit','python.plugin') for f in finds))
                entities.extend(ents);audit.extend(finds)
            else:
                ext=p.suffix.lower() or '(none)'
                analysis_info['unsupported'][ext]=analysis_info['unsupported'].get(ext,0)+1
        else:
            kind=category(rel)
            analysis_info['skipped'][kind]=analysis_info['skipped'].get(kind,0)+1
        with open_source(p) as stream: final_stat=os.fstat(stream.fileno())
        if (st.st_ino,st.st_size,st.st_mtime_ns)!=(final_stat.st_ino,final_stat.st_size,final_stat.st_mtime_ns):
            raise ValueError('Файл изменился во время анализа; повторите операцию')

    baseline_digest = compute_project_digest(files)

    functions_count = sum(1 for e in entities if e.kind in ("function", "async_function"))
    classes_count = sum(1 for e in entities if e.kind == "class")

    from .audit_rules import finding, deduplicate
    for fi in files:
        if fi.is_secret and eligible_analysis(fi.path):audit.append(finding('secret_file',fi.path))
    audit=deduplicate(audit)

    return SnapshotResult(
        created_at=created_at,
        description=description,
        total_files=total_files,
        python_files=python_files,
        total_bytes=total_bytes,
        functions_count=functions_count,
        classes_count=classes_count,
        sqlite_files=sqlite_files,
        log_files=log_files,
        last_mtime=last_mtime,
        baseline_digest=baseline_digest,
        files=files,
        entities=entities,
        audit=audit,
        analysis_info=analysis_info,
    )


def save_snapshot(conn: sqlite3.Connection, snap: SnapshotResult) -> int:
    cur = conn.execute(
        """
        INSERT INTO snapshots (
          created_at, description, agent_root,
          total_files, python_files, total_bytes,
          functions_count, classes_count, sqlite_files, log_files,
          last_mtime, baseline_digest, changes_from_prev
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            snap.created_at,
            snap.description,
            str(settings.agent_root),
            snap.total_files,
            snap.python_files,
            snap.total_bytes,
            snap.functions_count,
            snap.classes_count,
            snap.sqlite_files,
            snap.log_files,
            snap.last_mtime,
            snap.baseline_digest,
            0,
        ),
    )
    snapshot_id = int(cur.lastrowid)
    conn.execute("UPDATE snapshots SET analysis_info=? WHERE id=?",(__import__("json").dumps(snap.analysis_info),snapshot_id))
    import json
    metrics={}
    for file in snap.files:
        bucket=metrics.setdefault(file.file_category,{'files':0,'bytes':0,'python_files':0,'functions':0,'classes':0})
        bucket['files']+=1;bucket['bytes']+=file.size
        if file.file_type=='python': bucket['python_files']+=1
    for entity in snap.entities:
        bucket=metrics[category(entity.path)]
        if entity.kind=='class': bucket['classes']+=1
        else: bucket['functions']+=1
    status='incomplete' if any(f.sha256 is None for f in snap.files) else 'metadata_only'
    conn.execute("UPDATE snapshots SET project_id=?,category_metrics=?,content_status=? WHERE id=?", (settings.project_id,json.dumps(metrics),status,snapshot_id))

    conn.executemany(
        """
        INSERT INTO snapshot_files (snapshot_id, path, size, mtime, sha256, is_dir, file_type, lines, is_secret, file_category)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        [
            (
                snapshot_id,
                f.path,
                f.size,
                f.mtime,
                f.sha256,
                0,
                f.file_type,
                f.lines,
                1 if f.is_secret else 0,
                f.file_category,
            )
            for f in snap.files
        ],
    )

    conn.executemany(
        """
        INSERT INTO python_entities (
            snapshot_id, path, kind, name, qualname, lineno, end_lineno,
            signature, docstring, decorators, imports, calls,
            risk_level, risk_reasons, analyzer_id
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        [
            (
                snapshot_id,
                e.path,
                e.kind,
                e.name,
                e.qualname,
                e.lineno,
                e.end_lineno,
                e.signature,
                e.docstring,
                "\n".join(e.decorators or []),
                "\n".join(e.imports or []),
                "\n".join(e.calls or []),
                e.risk_level,
                "\n".join(e.risk_reasons or []),
                e.analyzer_id,
            )
            for e in snap.entities
        ],
    )

    from .audit_service import store_findings
    store_findings(conn,snapshot_id,snap.audit)

    return snapshot_id


def compare_snapshots(conn: sqlite3.Connection, a_id: int, b_id: int) -> dict[str, Any]:
    a_files = {
        r["path"]: r
        for r in conn.execute(
            "SELECT path,size,mtime,sha256,file_type,is_secret FROM snapshot_files WHERE snapshot_id=?",
            (a_id,),
        )
    }
    b_files = {
        r["path"]: r
        for r in conn.execute(
            "SELECT path,size,mtime,sha256,file_type,is_secret FROM snapshot_files WHERE snapshot_id=?",
            (b_id,),
        )
    }

    added = sorted(set(b_files) - set(a_files))
    deleted = sorted(set(a_files) - set(b_files))

    modified: list[str] = []
    size_changed: list[str] = []
    hash_changed: list[str] = []

    for p in sorted(set(a_files) & set(b_files)):
        ar = a_files[p]
        br = b_files[p]
        if (ar["sha256"] or "") != (br["sha256"] or ""):
            hash_changed.append(p)
        if ar["size"] != br["size"]:
            size_changed.append(p)
        if p in hash_changed or p in size_changed:
            modified.append(p)

    # potential renames: match deleted->added by sha256
    renames: list[tuple[str, str]] = []
    a_by_hash: dict[str, str] = {}
    b_by_hash: dict[str, str] = {}
    for p in deleted:
        h = a_files[p]["sha256"]
        if h:
            a_by_hash[h] = p
    for p in added:
        h = b_files[p]["sha256"]
        if h:
            b_by_hash[h] = p
    for h, oldp in a_by_hash.items():
        if h in b_by_hash:
            renames.append((oldp, b_by_hash[h]))

    # python diff: functions/classes added/removed in modified python files
    def ents(sid: int, path: str) -> set[str]:
        rows = conn.execute(
            "SELECT kind, COALESCE(qualname,name) AS qn FROM python_entities WHERE snapshot_id=? AND path=? AND kind IN ('function','async_function','class')",
            (sid, path),
        )
        return {f"{r['kind']}::{r['qn']}" for r in rows}

    py_changes: dict[str, Any] = {}
    for p in modified:
        if (a_files[p]["file_type"] == "python") or (b_files[p]["file_type"] == "python"):
            ea = ents(a_id, p)
            eb = ents(b_id, p)
            py_changes[p] = {
                "added": sorted(eb - ea),
                "removed": sorted(ea - eb),
            }

    return {
        "a": a_id,
        "b": b_id,
        "added": added,
        "deleted": deleted,
        "modified": modified,
        "size_changed": size_changed,
        "hash_changed": hash_changed,
        "renames": renames,
        "py_changes": py_changes,
    }


# ----------------- Backup -----------------


def create_backup(snapshot_id: int | None = None) -> dict[str, Any]:
    settings.backups_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    from uuid import uuid4
    base = f"project_backup_{ts}_{uuid4().hex}"
    archive = settings.backups_dir / f"{base}.tar.gz"
    sha_file = settings.backups_dir / f"{base}.sha256"

    # Legacy full archive, now uses the shared policy. Not the stage-4 backup engine.
    import hashlib
    from .filesystem import validate_project
    validate_project(settings.agent_root, settings)
    with archive.open('xb') as output:
        archive.chmod(0o600)
        with tarfile.open(fileobj=output, mode='w:gz', dereference=False) as tar:
            for path, st in iter_files(settings.agent_root):
                rel=path.relative_to(settings.agent_root)
                with open_source(path) as stream:
                    info=tarfile.TarInfo((Path(settings.agent_root.name)/rel).as_posix())
                    info.size=os.fstat(stream.fileno()).st_size
                    info.mtime=st.st_mtime
                    info.mode=st.st_mode & 0o777
                    tar.addfile(info,stream)
    digest=hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
    sha=digest.hexdigest()

    sha_file.write_text(f"{sha}  {archive.name}\n", encoding="utf-8")

    sha_file.chmod(0o600)
    st = archive.stat()
    return {
        "created_at": _now(),
        "snapshot_id": snapshot_id,
        "archive_path": str(archive),
        "archive_size": st.st_size,
        "sha256": sha,
        "warning": "⚠️ Архив может содержать секреты. Хранить безопасно.",
    }


def save_backup(conn: sqlite3.Connection, b: dict[str, Any]) -> int:
    cur = conn.execute(
        """
        INSERT INTO backups (created_at, snapshot_id, archive_path, archive_size, sha256, warning)
        VALUES (?,?,?,?,?,?)
        """,
        (
            b["created_at"],
            b.get("snapshot_id"),
            b["archive_path"],
            b["archive_size"],
            b["sha256"],
            b.get("warning"),
        ),
    )
    return int(cur.lastrowid)


# ----------------- Read-only helpers for logs/sqlite -----------------


def tail_text_file(path: Path, lines: int = 200, max_bytes: int = 2*1024*1024):
    with open_source(path) as stream:
        size=os.fstat(stream.fileno()).st_size
        stream.seek(max(0,size-max_bytes))
        data=stream.read(max_bytes)
    return '\n'.join(data.decode('utf-8',errors='replace').splitlines()[-max(1,min(lines,2000)):])


def sqlite_info(path: Path) -> dict[str, Any]:
    from .data_views import sqlite_inspect
    try:return sqlite_inspect(path)
    except (OSError,ValueError,sqlite3.Error):
        return {'path':str(path),'tables':[],'error':'inspection.sqlite'}
