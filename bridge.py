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

from pydantic import BaseModel, Field
import re

class AnalysisQuery(BaseModel):
    sql: str = Field(min_length=1, max_length=4000)

@app.post("/analyze")
def analyze(query: AnalysisQuery):
    sql = query.sql.strip().rstrip(";").strip()

    # Only allow a single SELECT statement.
    if not re.match(r"(?is)^select\s", sql):
        raise HTTPException(400, "Only SELECT queries are allowed")

    if ";" in sql or "--" in sql or "/*" in sql:
        raise HTTPException(400, "Multiple statements and comments are not allowed")

    forbidden = re.search(
        r"\b(read_csv|read_parquet|read_json|sqlite_scan|postgres_scan|"
        r"query|httpfs|install|load|attach|copy|export|pragma|"
        r"create|drop|alter|insert|update|delete|call|"
        r"write_file|read_text|read_blob)\b",
        sql, re.IGNORECASE
    )
    if forbidden:
        raise HTTPException(400, "Unsupported SQL operation")


    # Parse SQL and restrict access to approved tables.
    import sqlglot
    from sqlglot import exp

    try:
        statements = sqlglot.parse(sql, read="duckdb")
        if len(statements) != 1 or not isinstance(statements[0], exp.Select):
            raise ValueError("Only one SELECT statement is allowed")

        tree = statements[0]

        # Reject SQL constructs that are not needed for analysis.
        if any(isinstance(node, (exp.Command, exp.Into)) for node in tree.walk()):
            raise ValueError("Unsupported SQL operation")

        allowed_tables = {
            "agency_dim", "agency_rollup_by_period", "budget_history",
            "category_dim", "column_dict", "cumulative_schedule_variance",
            "data_build", "fms_location", "fms_sponsor",
            "latest_project_state", "lifetime_budget_variance", "meta",
            "original_budget", "pid_funding", "project_budget_fy",
            "raw_budget_fy", "raw_budget_history", "raw_project_detail",
            "raw_schedule_history", "schedule_budget_link",
            "schedule_history", "schedule_source_coverage",
            "source_schedule_history"
        }

        for table in tree.find_all(exp.Table):
            if table.db or table.catalog:
                raise ValueError("Qualified table names are not allowed")
            if table.name.lower() not in allowed_tables:
                raise ValueError("Table not allowed: " + table.name)

        # Disallow function calls outside this approved set.
        allowed_functions = {
            "COUNT", "SUM", "AVG", "MIN", "MAX", "ROUND",
            "COALESCE", "ABS", "LOWER", "UPPER", "LENGTH",
            "SUBSTRING", "CAST", "TRY_CAST", "DATE_TRUNC",
            "EXTRACT", "NULLIF"
        }

        for func in tree.find_all(exp.Func):
            if func.sql_name().upper() not in allowed_functions:
                raise ValueError("Function not allowed: " + func.sql_name())

    except (sqlglot.errors.ParseError, ValueError) as exc:
        raise HTTPException(400, str(exc))

    con = duckdb.connect("var/cpd.duckdb", read_only=True)
    try:
        con.execute("SET enable_external_access = false")
        con.execute("SET memory_limit = '256MB'")
        con.execute("SET threads = 2")
        result = con.execute(
            f"SELECT * FROM ({sql}) AS analysis_result LIMIT 200"
        )
        columns = [item[0] for item in result.description]
        rows = result.fetchall()

        return {
            "columns": columns,
            "rows": [dict(zip(columns, row)) for row in rows],
            "returned_rows": len(rows),
            "limit": 200
        }
    except Exception as exc:
        raise HTTPException(400, str(exc))
    finally:
        con.close()
