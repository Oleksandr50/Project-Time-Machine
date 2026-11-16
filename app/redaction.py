"""Conservative display masking; never rewrites source files or stored objects."""
import re
ASSIGN=re.compile(r'''(?im)(\b(?:api[_-]?key|password|passwd|secret|[a-z_]*token)\b["']?(?:\s*:\s*[\w\[\]., |]+)?\s*[:=]\s*)(["'])([^\r\n]*?)(\2)''')
BARE=re.compile(r'(?im)(\b(?:api[_-]?key|password|passwd|secret|[a-z_]*token)\b\s*[:=]\s*)(?!["\'])([^\s,;#]+)')
KEY=re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',re.S)
TOKEN=re.compile(r'\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|AIza[A-Za-z0-9_-]{20,})\b')
AUTH=re.compile(r'(?im)(\b(?:authorization|proxy-authorization)\s*[:=]\s*["\']?(?:bearer|basic)\s+)[^\s,"\']+')
URL_AUTH=re.compile(r'(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@')
PERSONAL=re.compile(r'(?i)(\b(?:email|phone|address|cookie|session[_-]?id)\b["\']?\s*[:=]\s*)(?:["\'][^"\'\r\n]*["\']|[^\s,;]+)')
SENSITIVE=re.compile(r'(?i)(?:password|passwd|secret|token|credential|api.?key|private.?key|ssh.?key|access.?key|authorization|cookie|session|email|phone|address|username|full.?name|first.?name|last.?name|salt|hash)')
PARTIAL=re.compile(r'''(?im)(\b(?:api[_-]?key|password|passwd|secret|[a-z_]*token)\b["']?\s*[:=]\s*)(["'])([^\r\n]*)''')


def redact(text):
    text=str(text)
    text=KEY.sub('[REDACTED PRIVATE KEY]',text)
    text=re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*\Z','[REDACTED PRIVATE KEY]',text,flags=re.S)
    text=AUTH.sub(lambda m:m[1]+'[REDACTED]',text)
    text=URL_AUTH.sub(lambda m:m[1]+'[REDACTED]@',text)
    text=PERSONAL.sub(lambda m:m[1]+'[REDACTED]',text)
    text=ASSIGN.sub(lambda m:m[1]+m[2]+'[REDACTED]'+m[4],text)
    text=PARTIAL.sub(lambda m:m[0] if m[2] in m[3] else m[1]+m[2]+'[REDACTED]',text)
    text=BARE.sub(lambda m:m[1]+'[REDACTED]',text)
    return TOKEN.sub('[REDACTED TOKEN]',text)


def cell(column,value):
    if SENSITIVE.search(column):return '[REDACTED]'
    if value is None:return 'NULL'
    if isinstance(value,bytes):return '[BLOB]'
    return redact(str(value))[:4096]
