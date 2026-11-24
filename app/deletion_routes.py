from fastapi import APIRouter,Request,Form,HTTPException
from fastapi.responses import RedirectResponse
from . import projects,deletions,i18n
from .config import settings
from .ui import render

router=APIRouter()


@router.post('/projects/delete-preview')
def project_preview(request:Request,project_id:int=Form(...)):
    project=projects.get_project(project_id,include_disabled=True)
    if project['enabled']:raise ValueError('delete.active')
    return render(request,'delete_confirm.html',title_key='delete.project',deleting_project=project,archive=None,
                  confirmation_token=deletions.issue(request.state.user,project))


@router.post('/projects/delete')
def project_delete(request:Request,project_id:int=Form(...),confirmation_token:str=Form(default=''),confirmation:str=Form(default='')):
    deletions.delete_project(project_id,request.state.user,confirmation_token,confirmation)
    response=RedirectResponse('/projects',status_code=303);response.delete_cookie('ptm_active_project');return response


@router.post('/backups/delete-preview')
def archive_preview(request:Request,archive_id:int=Form(...)):
    project=projects.get_project(settings.project_id);archive=deletions.archive_row(archive_id)
    return render(request,'delete_confirm.html',title_key='delete.archive',deleting_project=project,archive=archive,
                  confirmation_token=deletions.issue(request.state.user,project,archive))


@router.post('/backups/delete')
def archive_delete(request:Request,archive_id:int=Form(...),confirmation_token:str=Form(default=''),confirmation:str=Form(default='')):
    try:deletions.delete_archive(settings.project_id,archive_id,request.state.user,confirmation_token,confirmation)
    except deletions.Dependencies as exc:raise HTTPException(400,i18n.tr('delete.dependencies',ids=exc.ids)) from None
    return RedirectResponse('/backups?project_id='+str(settings.project_id),status_code=303)
