"""Bounded server-side pages, whitelisted sorting and literal search."""
from dataclasses import dataclass
import math
from . import i18n


@dataclass
class TablePage:
    rows:list
    columns:list
    total:int
    page:int
    per_page:int
    pages:int
    sort:str
    order:str
    query:str
    filter_value:str=''


def options(request,columns,default):
    try:page=max(1,int(request.query_params.get('page','1')));size=int(request.query_params.get('per_page','25'))
    except ValueError:raise ValueError('error.table')
    if size not in (10,25,50,100) or page>1000000:raise ValueError('error.table')
    selected=request.query_params.get('columns','')
    if selected and (not set(selected.split(',')) <= {c['key'] for c in columns}):raise ValueError('error.table')
    sort=request.query_params.get('sort',default)
    order=request.query_params.get('order','desc' if default=='id' else 'asc')
    if sort not in {c['key'] for c in columns} or order not in ('asc','desc'):raise ValueError('error.table')
    return page,size,sort,order,request.query_params.get('q','')[:300]


def like(value):return '%'+value.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'


def sql_page(conn,request,table,columns,default='id',where='',params=(),search=(),filter_column=None,filter_values=(),map_row=None,sort_expressions=None):
    page,size,sort,order,query=options(request,columns,default)
    clauses=[where] if where else [];params=list(params)
    if query and search:
        clauses.append('('+' OR '.join(field+" LIKE ? ESCAPE '\\'" for field in search)+')');params.extend([like(query)]*len(search))
    selected=request.query_params.get('kind','')
    if selected:
        if not filter_column or selected not in filter_values:raise ValueError('error.table')
        clauses.append(filter_column+'=?');params.append(selected)
    condition=' WHERE '+' AND '.join(clauses) if clauses else ''
    total=conn.execute('SELECT COUNT(*) FROM '+table+condition,params).fetchone()[0]
    pages=max(1,math.ceil(total/size));page=min(page,pages)
    # Identifiers come exclusively from router-owned schemas, never interpolated user text.
    expression=(sort_expressions or {}).get(sort,'"'+sort+'"')
    rows=[dict(r) for r in conn.execute('SELECT * FROM '+table+condition+' ORDER BY '+expression+' '+order+',"'+('id' if any(c['key']=='id' for c in columns) else default)+'" '+order+' LIMIT ? OFFSET ?',[*params,size,(page-1)*size])]
    if map_row:rows=[map_row(row) for row in rows]
    return TablePage(rows,columns,total,page,size,pages,sort,order,query,selected)


def memory_page(request,rows,columns,default='id'):
    page,size,sort,order,query=options(request,columns,default)
    if query:rows=[r for r in rows if query.casefold() in ' '.join(str(v) for v in r.values()).casefold()]
    rows=sorted(rows,key=lambda r:(r.get(sort) is not None,r.get(sort) if r.get(sort) is not None else ''),reverse=order=='desc')
    total=len(rows);pages=max(1,math.ceil(total/size));page=min(page,pages)
    return TablePage(rows[(page-1)*size:page*size],columns,total,page,size,pages,sort,order,query)


def column(key,label,kind='text',**extra):return dict(key=key,label=label,kind=kind,**extra)
