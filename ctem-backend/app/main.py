from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import scans, assets, risk, peripherals, alerts, logs, ueba, agent

app = FastAPI(title="CTEM Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=r"^https?://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(assets.router)
app.include_router(risk.router)
app.include_router(peripherals.router)
app.include_router(alerts.router)
app.include_router(logs.router)
app.include_router(ueba.router)
app.include_router(agent.router)


@app.get("/health")
async def health(check_db: bool = False):
    if not check_db:
        return {"status": "ok"}
    db_status = "ok"
    try:
        from app.db.supabase_client import get_client
        client = get_client()
        client.table("assets").select("id").limit(1).execute()
    except Exception as e:
        db_status = f"database_error: {str(e)}"
    return {"status": "ok", "database": db_status}
