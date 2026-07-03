import os
import re
import decimal
import datetime
from typing import Any

import sqlparse
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from trino.dbapi import connect
from trino.auth import BasicAuthentication


app = FastAPI(title="Safe Trino Query Service")


TRINO_HOST = os.getenv("TRINO_HOST", "trino")
TRINO_PORT = int(os.getenv("TRINO_PORT", "8080"))
TRINO_USER = os.getenv("TRINO_USER", "ai_reader")
TRINO_PASSWORD = os.getenv("TRINO_PASSWORD", "")
TRINO_HTTP_SCHEME = os.getenv("TRINO_HTTP_SCHEME", "http")
TRINO_CATALOG = os.getenv("TRINO_CATALOG", "airc_coversheet")
TRINO_SCHEMA = os.getenv("TRINO_SCHEMA", "airc_coversheet_db")
TRINO_VERIFY_SSL = os.getenv("TRINO_VERIFY_SSL", "false").lower() == "true"

QUERY_API_KEY = os.getenv("QUERY_API_KEY", "")
MAX_ROWS = int(os.getenv("MAX_ROWS", "200"))
TIMEOUT_SECONDS = int(os.getenv("TIMEOUT_SECONDS", "30"))


ALLOWED_PREFIX = "airc_coversheet.airc_coversheet_db."


FORBIDDEN_KEYWORDS = [
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "CREATE",
    "TRUNCATE",
    "MERGE",
    "CALL",
    "EXECUTE",
    "GRANT",
    "REVOKE",
    "REPLACE",
    "SET",
    "RESET",
    "COMMIT",
    "ROLLBACK",
    "START",
    "PREPARE",
    "DEALLOCATE",
    "EXPLAIN ANALYZE",
]

FORBIDDEN_PATTERNS = [
    r"\bdrivers_to_hash\b",
    r"\bpassword\b",
    r"\bplain_password\b",
    r"\btoken\b",
    r"\bsecret\b",
    r"\bcredential\b",
    r"\bauth\b",
]


class QueryRequest(BaseModel):
    sql: str


def json_safe(value: Any) -> Any:
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return float(value)
    return value


def clean_sql(sql: str) -> str:
    sql = sql.strip()

    # Remove markdown fences if the model accidentally sends ```sql
    sql = re.sub(r"^```sql\s*", "", sql, flags=re.IGNORECASE)
    sql = re.sub(r"^```\s*", "", sql)
    sql = re.sub(r"\s*```$", "", sql)

    sql = sql.strip()

    # Allow only one trailing semicolon and remove it
    if sql.endswith(";"):
        sql = sql[:-1].strip()

    return sql


def validate_sql(sql: str) -> str:
    sql = clean_sql(sql)

    if not sql:
        raise HTTPException(status_code=400, detail="SQL is empty.")

    if len(sql) > 8000:
        raise HTTPException(status_code=400, detail="SQL is too long.")

    parsed = sqlparse.parse(sql)

    if len(parsed) != 1:
        raise HTTPException(status_code=400, detail="Only one SQL statement is allowed.")

    statement = parsed[0]
    first_token = statement.token_first(skip_cm=True)

    if not first_token:
        raise HTTPException(status_code=400, detail="Invalid SQL.")

    first_word = first_token.value.upper()

    if first_word not in ["SELECT", "WITH"]:
        raise HTTPException(status_code=400, detail="Only SELECT or WITH queries are allowed.")

    upper_sql = sql.upper()

    # Block dangerous keywords
    for keyword in FORBIDDEN_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", upper_sql):
            raise HTTPException(status_code=400, detail=f"Forbidden SQL keyword: {keyword}")

    # Block sensitive tables/fields
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, sql, flags=re.IGNORECASE):
            raise HTTPException(
                status_code=400,
                detail="Query references a forbidden table or sensitive field.",
            )

    # Force use of the allowed database
    if ALLOWED_PREFIX not in sql:
        raise HTTPException(
            status_code=400,
            detail=f"Query must use fully qualified tables under {ALLOWED_PREFIX}",
        )

    # Prevent multiple statements separated by semicolon inside the query
    if ";" in sql:
        raise HTTPException(status_code=400, detail="Semicolons are not allowed inside SQL.")

    # Add LIMIT if missing.
    # For aggregate queries, LIMIT is harmless.
    if not re.search(r"\bLIMIT\s+\d+\b", upper_sql):
        sql = f"{sql}\nLIMIT {MAX_ROWS}"

    return sql


def get_connection():
    auth = None

    if TRINO_PASSWORD:
        auth = BasicAuthentication(TRINO_USER, TRINO_PASSWORD)

    return connect(
        host=TRINO_HOST,
        port=TRINO_PORT,
        user=TRINO_USER,
        catalog=TRINO_CATALOG,
        schema=TRINO_SCHEMA,
        http_scheme=TRINO_HTTP_SCHEME,
        auth=auth,
        verify=TRINO_VERIFY_SSL,
        request_timeout=TIMEOUT_SECONDS,
    )


@app.get("/health")
def health():
    return {"ok": True, "service": "trino-query-service"}


@app.post("/query")
def query_trino(
    payload: QueryRequest,
    authorization: str | None = Header(default=None),
):
    if QUERY_API_KEY:
        expected = f"Bearer {QUERY_API_KEY}"

        if authorization != expected:
            raise HTTPException(status_code=401, detail="Unauthorized.")

    safe_sql = validate_sql(payload.sql)

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(safe_sql)

        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description] if cur.description else []

        result = []

        for row in rows:
            item = {}

            for col, val in zip(columns, row):
                item[col] = json_safe(val)

            result.append(item)

        return {
            "ok": True,
            "sql_executed": safe_sql,
            "columns": columns,
            "row_count": len(result),
            "rows": result,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
