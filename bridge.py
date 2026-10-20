from fastapi import FastAPI, Header, HTTPException, Depends
import duckdb
import os
import secrets
from pathlib import Path

def verify_key(authorization: str | None = Header(default=None)):
    expected = os.environ.get("BRIDGE_API_KEY") or Path(".bridge_secret").read_text().strip()
    provided = authorization.removeprefix("Bearer ") if authorization else ""
    if not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")

app = FastAPI(
    dependencies=[Depends(verify_key)],
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

@app.get("/")
def read_root():
    db_path = "var/cpd.duckdb"
    if not os.path.exists(db_path):
        return {"error": "Database not found"}

    con = duckdb.connect(db_path, read_only=True)
    tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
    summary = {}
    for t in tables:
        try:
            count = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            summary[t] = count
        except Exception:
            summary[t] = "table"
    con.close()
    return {"status": "Active", "database": db_path, "tables": summary}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
