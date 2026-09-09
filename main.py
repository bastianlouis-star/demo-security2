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
    # ❌ DANGEREUX : valeur non standard, autorise l'affichage du site dans
    # n'importe quelle iframe (clickjacking) -> doit être DENY ou SAMEORIGIN
    response.headers['X-Frame-Options'] = 'ALLOWALL'
    return response


if __name__ == '__main__':
    uvicorn.run('main:app', reload=True)