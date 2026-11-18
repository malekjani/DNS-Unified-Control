"""Fixed endpoints shared by Web and TUI through the privileged Unix agent."""
from __future__ import annotations
from fastapi import HTTPException, Request
from . import controller


def request_args(body):
    if not isinstance(body,dict) or set(body)-{'mode','engines','listen_ip','confirm'}:
        raise HTTPException(422,'Invalid mode request')
    mode=body.get('mode');engines=body.get('engines')
    if mode not in ('exclusive','multi') or not isinstance(engines,list) or any(type(x) is not str for x in engines):
        raise HTTPException(422,'Invalid mode/engine selection')
    if not (1 <= len(engines)<=7) or len(set(engines))!=len(engines):
        raise HTTPException(422,'Use 1..7 distinct engines')
    listen=body.get('listen_ip')
    if listen is not None and (type(listen) is not str or len(listen)>45):
        raise HTTPException(422,'Bad listen IP')
    return mode,engines,listen


def install_agent_routes(app):
    @app.get('/multi/status')
    def multi_status():return controller.status()

    @app.post('/multi/plan')
    def multi_plan(body:dict):
        mode,engines,listen=request_args(body)
        try:return controller.plan(mode,engines,listen)
        except ValueError as exc:raise HTTPException(422,str(exc))

    @app.post('/multi/apply')
    def multi_apply(body:dict):
        mode,engines,listen=request_args(body)
        if body.get('confirm')!='yes':raise HTTPException(422,'Only explicit yes is accepted')
        try:return controller.apply(mode,engines,listen,confirm='yes')
        except (ValueError,PermissionError) as exc:raise HTTPException(422,str(exc))


def install_web_routes(app,guard,agent_request,static_dir):
    from fastapi.responses import FileResponse
    @app.get('/multi.js')
    async def multi_js():return FileResponse(static_dir/'multi.js',media_type='text/javascript')

    @app.get('/multi.css')
    async def multi_css():return FileResponse(static_dir/'multi.css',media_type='text/css')

    @app.get('/api/multi/status')
    async def multi_status(request:Request):
        guard(request)
        return await agent_request('GET','/multi/status')

    @app.post('/api/multi/plan')
    async def multi_plan(request:Request):
        guard(request)
        body=await request.json()
        request_args(body)
        return await agent_request('POST','/multi/plan',body)

    @app.post('/api/multi/apply')
    async def multi_apply(request:Request):
        guard(request,True)  # must be MFA-authenticated and have valid CSRF
        body=await request.json()
        request_args(body)
        if body.get('confirm')!='yes':raise HTTPException(422,'Explicit yes required')
        return await agent_request('POST','/multi/apply',body,timeout=90)
