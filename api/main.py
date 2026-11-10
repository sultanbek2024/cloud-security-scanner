"""
FastAPI қосымшасының негізгі кіру нүктесі (Application Entry Point).
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from api.routes import router

app = FastAPI(
    title="Cloud Security Scanner & CSPM Platform",
    description="Бұлттық инфрақұрылымның конфигурациялық осалдықтарын анықтау, IaC талдау және Drift анықтау жүйесі.",
    version="2.0.0",
)

# CORS рұқсаттары
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Маршруттарды қосу
app.include_router(router)


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
def serve_dashboard():
    """Интерактивті веб-интерфейсті қайтарады."""
    web_index = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "index.html")
    if os.path.exists(web_index):
        return FileResponse(web_index)
    return {"message": "Web UI табылмады. /docs арқылы API қолданыңыз."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
