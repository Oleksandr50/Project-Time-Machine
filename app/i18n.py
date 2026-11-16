"""Data-driven catalog discovery. Locale is scoped to one request, including worker calls."""
from contextvars import ContextVar
from pathlib import Path
import json
import re
from string import Formatter

DIRECTORY=Path(__file__).resolve().with_name('locales')
CATALOGS={p.stem:json.loads(p.read_text(encoding='utf-8')) for p in sorted(DIRECTORY.glob('*.json'))}
LANGUAGES=tuple(CATALOGS)
current_locale=ContextVar('ptm_locale',default='ru')
REVERSE={value:key for key,value in CATALOGS['ru'].items()}
PATTERNS=[(re.compile('^'+re.escape(value).replace(re.escape('{value}'),'(.*)')+'$'),key)
          for key,value in CATALOGS['ru'].items() if '{value}' in value]


def tr(key,locale=None,**values):
    locale=locale or current_locale.get()
    text=CATALOGS.get(locale,CATALOGS['en']).get(key,CATALOGS['en'].get(key,key))
    return text.format(**values) if values else text


def message(value,locale=None):
    value=str(value)
    if value in CATALOGS['en']:return tr(value,locale)
    if value in REVERSE:return tr(REVERSE[value],locale)
    for pattern,key in PATTERNS:
        match=pattern.fullmatch(value)
        if match:return tr(key,locale,value=match.group(1))
    return value


def detect(request):
    value=request.query_params.get('lang') or request.cookies.get('ptm_language')
    if value in CATALOGS:return value
    choices=[]
    for item in request.headers.get('accept-language','').split(','):
        parts=item.strip().split(';');code=parts[0].lower().split('-')[0]
        try:weight=float(parts[1].split('=')[1]) if len(parts)>1 else 1.0
        except (ValueError,IndexError):continue
        if code in CATALOGS and weight>0:choices.append((weight,code))
    return max(choices,key=lambda p:p[0])[1] if choices else 'ru'


def placeholders(value):return {name for _,name,_,_ in Formatter().parse(value) if name}


for code,catalog in CATALOGS.items():
    if set(catalog)!=set(CATALOGS['en']):raise ValueError('Incomplete locale catalog: '+code)
    for key,value in catalog.items():
        if not isinstance(value,str) or placeholders(value)!=placeholders(CATALOGS['en'][key]):
            raise ValueError('Invalid locale placeholders: '+code+':'+key)
