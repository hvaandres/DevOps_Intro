"""Azure SQL Database data endpoints — read-only access with pagination."""
import json
import logging
import os
import struct

import azure.functions as func

bp = func.Blueprint()
logger = logging.getLogger(__name__)


def _get_sql_connection():
    """
    Create a pyodbc connection to Azure SQL using Managed Identity (AAD token).
    Requires pyodbc and the ODBC Driver 18 for SQL Server.
    """
    import pyodbc
    from azure.identity import DefaultAzureCredential

    server = os.environ.get("SQL_SERVER_FQDN", "")
    database = os.environ.get("SQL_DATABASE_NAME", "")

    # Acquire AAD token for Azure SQL
    credential = DefaultAzureCredential()
    token = credential.get_token("https://database.windows.net/.default")
    token_bytes = token.token.encode("UTF-16-LE")
    token_struct = struct.pack(f"<I{len(token_bytes)}s", len(token_bytes), token_bytes)

    conn_str = (
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={server};"
        f"DATABASE={database};"
    )
    conn = pyodbc.connect(conn_str, attrs_before={1256: token_struct})
    return conn


@bp.route(route="sql-data", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def query_sql(req: func.HttpRequest) -> func.HttpResponse:
    """
    Query SQL database with offset-based pagination.

    Query params:
        - table: table/view name to query (required, validated against allowlist)
        - page: page number (default: 1)
        - page_size: rows per page (default: 100, max: 1000)
        - order_by: column to sort by (default: "id")
    """
    try:
        table = req.params.get("table", "")
        page = max(int(req.params.get("page", "1")), 1)
        page_size = min(int(req.params.get("page_size", "100")), 1000)
        order_by = req.params.get("order_by", "id")

        # Allowlist of queryable tables/views — prevent SQL injection
        allowed_tables = os.environ.get("SQL_ALLOWED_TABLES", "").split(",")
        if not table or table not in allowed_tables:
            return func.HttpResponse(
                body=json.dumps({
                    "error": f"Table '{table}' is not available. Allowed: {allowed_tables}"
                }),
                mimetype="application/json",
                status_code=400,
            )

        # Allowlist columns for ORDER BY
        allowed_columns = os.environ.get("SQL_ALLOWED_COLUMNS", "id").split(",")
        if order_by not in allowed_columns:
            order_by = "id"

        offset = (page - 1) * page_size

        conn = _get_sql_connection()
        cursor = conn.cursor()

        # Count total rows
        cursor.execute(f"SELECT COUNT(*) FROM [{table}]")  # noqa: S608 — table is allowlisted
        total = cursor.fetchone()[0]

        # Paginated query
        query = f"""
            SELECT * FROM [{table}]
            ORDER BY [{order_by}]
            OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
        """  # noqa: S608
        cursor.execute(query, offset, page_size)

        columns = [desc[0] for desc in cursor.description]
        rows = [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        return func.HttpResponse(
            body=json.dumps({
                "items": rows,
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": (total + page_size - 1) // page_size,
            }, default=str),
            mimetype="application/json",
            status_code=200,
        )

    except Exception:
        logger.exception("Error querying SQL")
        return func.HttpResponse(
            body=json.dumps({"error": "Internal server error"}),
            mimetype="application/json",
            status_code=500,
        )
