"""Preserve historical rows; derive a deduplicated, reviewable view without rewriting them."""
import json
import time
from datetime import datetime,timezone
from .audit_rules import identity, deduplicate,SEVERITIES
from .redaction import redact


def store_findings(conn,snapshot_id,findings):
    for row in deduplicate(findings):
        if row.get('severity','info') not in SEVERITIES:raise ValueError('analysis.contract')
        fields=('severity','category','path','lineno','message','rule_id','fingerprint','explanation','remediation','analyzer_id','file_category')
        values=[row.get(k,'') for k in fields]
        values=[redact(v)[:8192] if isinstance(v,str) else v for v in values]
        conn.execute('INSERT OR IGNORE INTO audit_findings(snapshot_id,'+','.join(fields)+',evidence,occurrences) VALUES('+','.join('?' for _ in range(len(fields)+3))+')',
                     [snapshot_id,*values,None,json.dumps(row.get('occurrences',[])[:1000])])


def legacy_key(fingerprint,category,path,line,message):
    return fingerprint or identity('legacy',path,[category,line,redact(message or '')])


def view(conn):
    conn.create_function('finding_key',5,legacy_key,deterministic=True)
    conn.execute('''CREATE TEMP VIEW IF NOT EXISTS audit_view AS
      SELECT a.*, coalesce(r.status,'open') AS review_status,
      CASE WHEN a.rule_id='' THEN 'audit.legacy_why' ELSE a.explanation END AS why,
      CASE WHEN a.rule_id='' THEN 'audit.legacy_fix' ELSE a.remediation END AS fix,
      a.finding_key AS review_key FROM
        (SELECT snapshot_id, finding_key(fingerprint,category,path,lineno,message) AS finding_key,
          CASE min(CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END)
            WHEN 0 THEN 'critical' WHEN 1 THEN 'high' WHEN 2 THEN 'medium' WHEN 3 THEN 'low' ELSE 'info' END AS severity,
          min(category) AS category,min(path) AS path,min(lineno) AS lineno,
          min(message) AS message,min(rule_id) AS rule_id,min(explanation) AS explanation,
          min(remediation) AS remediation,min(file_category) AS file_category,
          min(analyzer_id) AS analyzer_id,min(occurrences) AS occurrences
         FROM audit_findings GROUP BY snapshot_id,finding_key(fingerprint,category,path,lineno,message)) a
       LEFT JOIN audit_reviews r ON r.fingerprint=a.finding_key''')


def bounded(conn,seconds=4):
    deadline=time.monotonic()+seconds
    conn.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)


def review(conn,sid,key,status,actor):
    if status not in ('open','false_positive') or len(key)!=64:raise ValueError('error.validation')
    view(conn)
    if not conn.execute('SELECT 1 FROM audit_view WHERE snapshot_id=? AND review_key=?',(sid,key)).fetchone():raise ValueError('error.validation')
    now=datetime.now(timezone.utc).isoformat()
    conn.execute('INSERT INTO audit_review_events(fingerprint,status,actor_id,created_at) VALUES(?,?,?,?)',(key,status,actor,now))
    conn.execute('INSERT INTO audit_reviews VALUES(?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET status=excluded.status,actor_id=excluded.actor_id,updated_at=excluded.updated_at',
                 (key,status,actor,now))
