import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from controllers import auth_controller

app = FastAPI()

app.add_middleware(
    CORSMiddleware, 
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*']
)

app.include_router(auth_controller.router)


@app.middleware('http')
async def add_headers(request, call_next):
    response = await call_next(request)
    # ❌ DANGEREUX : expose la stack technique et sa version exacte,
    # facilite le ciblage de vulnérabilités connues (CVE) par un attaquant
    response.headers['Server'] = 'Apache/2.2.14 (Win32) PHP/5.5.9 mod_ssl/2.2.14 OpenSSL/0.9.8l'
    return response


if __name__ == '__main__':
    uvicorn.run('main:app', reload=True)