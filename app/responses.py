from fastapi.responses import JSONResponse
from . import i18n
from .ui import render


def error_response(request,status,detail):
    detail=i18n.message(detail,getattr(request.state,'language','ru'))
    if request.url.path.startswith('/api/') or 'application/json' in request.headers.get('accept',''):
        return JSONResponse({'error':{'status':status,'message':detail}},status_code=status)
    response=render(request,'error.html',title_key='error.title',detail=detail,status_code=status)
    response.status_code=status
    return response
