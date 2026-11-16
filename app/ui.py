"""Shared Jinja environment: translation, safe URLs and small display primitives."""
from datetime import datetime,timezone
from urllib.parse import urlencode,urlsplit,parse_qsl
from pathlib import Path
from jinja2 import pass_context
from fastapi.templating import Jinja2Templates
from . import i18n
from .redaction import redact

NAV=[('/', 'dashboard','◫'),('/projects','projects','▦'),('/snapshots','snapshots','◷'),
     ('/timeline','timeline','↳'),('/compare','compare','⇄'),('/backups','backups','▤'),
     ('/restore','restore','↶'),('/files','files','▱'),('/functions','analysis','⌘'),
     ('/audit','audit','◇'),('/logs','logs','≡'),('/settings','settings','⚙')]
PROJECT_ROUTES={p for p,_,_ in NAV if p!='/settings'}|{'/file','/compare/text','/logs/view','/sqlite','/report','/api/status','/api/jobs','/restore/preview','/audit/export'}
QUERY_KEYS={'project_id','snapshot_id','page','per_page','q','sort','order','prefix','kind','severity','risk','a','b','path','status','type','columns','section','jobs_page','preview_id','history_page','source','baseline','new_only','category','review','entity','scope','n','log_q','level','table','records_page','records_per_page','audit_change'}


def clean_query(request):return {k:v for k,v in request.query_params.items() if k in QUERY_KEYS}


def safe_return(value):
    parsed=urlsplit(value)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith('/') or parsed.path.startswith('//') or '\\' in value or any(ord(c)<32 for c in value):return '/'
    if parsed.path not in PROJECT_ROUTES|{'/account','/admin/users','/settings'}:return '/'
    values={k:v for k,v in parse_qsl(parsed.query) if k in QUERY_KEYS}
    return parsed.path+('?' + urlencode(values) if values else '')


def return_url(request):
    params=clean_query(request)
    return request.url.path+('?' + urlencode(params) if params else '')


@pass_context
def translate(ctx,key,**values):return i18n.tr(key,getattr(ctx['request'].state,'language','ru'),**values)


@pass_context
def url(ctx,endpoint,**params):
    req=ctx['request'];project=getattr(req.state,'project',None)
    if project and (endpoint in PROJECT_ROUTES or endpoint.startswith(('/actions/','/projects/','/backups/','/restore/','/audit/'))):params.setdefault('project_id',project['id'])
    return endpoint+('?' + urlencode({k:v for k,v in params.items() if v is not None and v!=''}) if params else '')


@pass_context
def page_url(ctx,**changes):
    req=ctx['request'];params=clean_query(req);params.update(changes)
    return url(ctx,req.url.path,**params)


def compact(value,limit=55):
    value=str(value or '')
    return value if len(value)<=limit else value[:max(8,limit//3)]+'…'+value[-max(8,limit-limit//3-1):]


def bytes_label(value):
    value=float(value or 0)
    for unit in ('B','KiB','MiB','GiB','TiB'):
        if value<1024:return f'{value:.1f} {unit}' if unit!='B' else f'{int(value)} B'
        value/=1024
    return f'{value:.1f} PiB'


def event_label(value):
    suffix=''
    for ending in ('_started','_failed'):
        if value.endswith(ending):value=value[:-len(ending)];suffix=' · '+i18n.tr('outcome.'+ending[1:]);break
    return i18n.tr('event.'+value)+suffix


def details_label(value):
    import json
    try:data=json.loads(value)
    except (ValueError,TypeError):return ''
    labels=[]
    for key,item in data.items():
        label=i18n.tr('auth.allowed' if key=='allowed' else 'auth.'+key)
        if isinstance(item,bool):item=i18n.tr('common.yes' if item else 'common.no')
        elif key.endswith('_role'):item=i18n.tr('role.'+str(item))
        labels.append(label+': '+str(item))
    return ' · '.join(labels)


def context(request):
    user=getattr(request.state,'user',None)
    locale=getattr(request.state,'language','ru')
    prefs=user or {}
    theme=prefs.get('theme') or request.cookies.get('ptm_theme','system')
    if theme not in ('system','dark','light'):theme='system'
    return {'nav':NAV,'locale':locale,'language_options':[(c,d['language_name']) for c,d in i18n.CATALOGS.items()],
            'theme':theme,'scale':prefs.get('scale',100),'return_to':return_url(request)}



def environment():
    templates=Jinja2Templates(directory=str(Path(__file__).resolve().with_name('templates')),context_processors=[context])
    templates.env.globals.update(t=translate,url=url,page_url=page_url)
    templates.env.filters.update(redact=redact,compact=compact,bytes=bytes_label,localize=i18n.message,event=event_label,details=details_label)
    templates.env.filters['utc']=lambda v:datetime.fromtimestamp(v,timezone.utc).isoformat(timespec='seconds') if v is not None else '—'
    return templates


templates=environment()


def render(request,name,**context):return templates.TemplateResponse(request=request,name=name,context={'request':request,**context})
