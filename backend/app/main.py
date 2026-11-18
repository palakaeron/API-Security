from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.config import get_settings
from app.database import get_engine, get_session_factory
from app.models import Api
from app.routers import apis, projects, scans

settings = get_settings()


class DiscoveryImportRequest(BaseModel):
    api_id: int = Field(gt=0)
    format: str
    content: str = Field(min_length=2)


class TrafficObservation(BaseModel):
    """A single HTTP request observed via captured traffic."""

    method: str = Field(min_length=1, max_length=10)
    path: str = Field(min_length=1, max_length=2048)


class TrafficRecordRequest(BaseModel):
    """Batch of traffic observations to record for an api_id."""

    api_id: int = Field(gt=0)
    observations: list[TrafficObservation] = Field(min_length=1)


app = FastAPI(
    title="API Security & Risk Intelligence Platform",
    description="Defensive, evidence-first API security testing for a controlled local lab.",
    version="0.1.0",
)


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return validation details without echoing untrusted request values."""
    del request
    detail = [
        {key: error[key] for key in ("type", "loc", "msg") if key in error}
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": detail},
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(projects.router)
app.include_router(apis.router)
app.include_router(scans.router)


def _require_api_exists(api_id: int) -> None:
    with get_session_factory(settings.database_url)() as database:
        if database.get(Api, api_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="api not found")


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "alive", "service": "api-security-backend"}


@app.post("/discovery/import", tags=["discovery"])
def import_discovery(request: DiscoveryImportRequest) -> dict[str, int | str]:
    from app.discovery.models import ImportValidationError
    from app.discovery.parsers import parse_openapi, parse_postman
    from app.discovery.persistence import import_endpoints

    fmt = request.format.lower()
    if fmt not in {"openapi", "postman"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="format must be 'openapi' or 'postman'",
        )
    source = "spec" if fmt == "openapi" else "postman"
    _require_api_exists(request.api_id)
    try:
        endpoints = (
            parse_openapi(request.content) if source == "spec" else parse_postman(request.content)
        )
    except ImportValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    count = import_endpoints(
        get_engine(settings.database_url), request.api_id, endpoints, source
    )
    return {"imported": count, "source": source}


@app.post("/discovery/traffic", tags=["discovery"])
def record_traffic(request: TrafficRecordRequest) -> dict[str, int]:
    """Persist a batch of traffic-observed endpoint observations.

    Each observation is validated to ensure the path is syntactically sane,
    then stored as a ``source='traffic'`` endpoint row.  Duplicate rows (same
    api_id + path + method) are silently skipped due to the upsert strategy.
    """
    from app.discovery.models import DiscoveredEndpoint
    from app.discovery.persistence import import_endpoints

    _require_api_exists(request.api_id)
    valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    endpoints = []
    for obs in request.observations:
        method = obs.method.upper().strip()
        path = obs.path.strip()
        if method not in valid_methods:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"unsupported HTTP method: {method!r}",
            )
        if not path.startswith("/"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"path must start with '/': {path!r}",
            )
        endpoints.append(
            DiscoveredEndpoint(
                path=path,
                method=method,
                parameters=[],
                request_schema=None,
                response_schemas={},
                auth_scheme="none",
                deprecated=False,
            )
        )

    count = import_endpoints(
        get_engine(settings.database_url), request.api_id, endpoints, "traffic"
    )
    return {"recorded": count}


@app.get("/discovery/diff/{api_id}", tags=["discovery"])
def get_diff(api_id: int) -> dict[str, object]:
    """Return shadow and zombie endpoint findings for the given api_id.

    - **shadow**: endpoints seen in captured traffic but not declared in the spec.
    - **zombie**: deprecated spec endpoints that have also appeared in traffic.
    """
    from app.discovery.diff import diff_endpoints

    result = diff_endpoints(get_engine(settings.database_url), api_id)
    return {
        "api_id": result.api_id,
        "shadow": [{"path": e.path, "method": e.method} for e in result.shadow],
        "zombie": [{"path": e.path, "method": e.method} for e in result.zombie],
    }
