"""Local-only intentionally vulnerable API lab with paired secured routes."""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from graphql import GraphQLField, GraphQLObjectType, GraphQLSchema, GraphQLString, graphql_sync
from pydantic import BaseModel, Field

from app.auth import (
    issue_secure_token,
    issue_vulnerable_token,
    secure_identity,
    vulnerable_identity,
)
from app.data import ORDERS, USERS

app = FastAPI(
    title="Synthetic API Security Lab",
    description="Local-only training targets. All data and credentials are synthetic.",
    version="1.0.0",
)

SERVICE_PREFIXES = {
    "auth": ("/health", "/vuln/auth", "/secure/auth"),
    "users": ("/health", "/vuln/users", "/secure/users", "/vuln/profiles", "/secure/profiles"),
    "admin": ("/health", "/vuln/admin", "/secure/admin"),
    "payments": ("/health", "/vuln/payments", "/secure/payments"),
    "orders": ("/health", "/vuln/orders", "/secure/orders"),
    "inventory": ("/health", "/v1", "/internal"),
    "graphql": ("/health", "/vuln/graphql", "/secure/graphql"),
}


@app.middleware("http")
async def limit_service_surface(request: Request, call_next: Any) -> Any:
    """Expose only one API domain when launched by the native lab runner."""
    service = os.environ.get("LAB_SERVICE")
    if service:
        allowed_prefixes = SERVICE_PREFIXES.get(service)
        if allowed_prefixes is None or not request.url.path.startswith(allowed_prefixes):
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"detail": "route not served by this lab API"},
            )
    return await call_next(request)


class LoginRequest(BaseModel):
    username: str = Field(pattern="^(alice|bob|admin)$")
    password: str = Field(min_length=1, max_length=128)


class ProfileUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=80)
    support_pin: str | None = Field(default=None, pattern="^\\d{4}$")
    role: str | None = Field(default=None, pattern="^(user|admin)$")


class GraphQLRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)


def _user_or_404(user_id: str) -> dict[str, Any]:
    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="synthetic user not found"
        )
    return user


def _public_profile(user: dict[str, Any]) -> dict[str, str]:
    return {
        "id": user["id"],
        "email": user["email"],
        "display_name": user["profile"]["display_name"],
    }


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "alive", "service": "synthetic-api-security-lab"}


@app.post("/vuln/auth/token", tags=["vulnerable"])
def vulnerable_login(login: LoginRequest) -> dict[str, str]:
    user = _user_or_404(login.username)
    return {
        "access_token": issue_vulnerable_token(user["id"], user["role"]),
        "token_type": "bearer",
    }


@app.post("/secure/auth/token", tags=["secure"])
def secure_login(login: LoginRequest) -> dict[str, str]:
    secret = os.environ.get("LAB_SECURE_JWT_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="secure lab secret unset"
        )
    user = _user_or_404(login.username)
    return {
        "access_token": issue_secure_token(user["id"], user["role"], secret),
        "token_type": "bearer",
    }


@app.get("/vuln/users/{user_id}", tags=["vulnerable"])
def vulnerable_user(user_id: str, request: Request) -> dict[str, Any]:
    vulnerable_identity(request)
    return _user_or_404(user_id)


@app.get("/secure/users/{user_id}", tags=["secure"])
def secure_user(user_id: str, request: Request) -> dict[str, str]:
    identity = secure_identity(request)
    if identity["sub"] != user_id and identity.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="object ownership required"
        )
    return _public_profile(_user_or_404(user_id))


@app.get("/vuln/admin/audit", tags=["vulnerable"])
def vulnerable_admin_audit(request: Request) -> dict[str, Any]:
    vulnerable_identity(request)
    return {"audit": "synthetic-admin-log", "user_count": len(USERS)}


@app.get("/secure/admin/audit", tags=["secure"])
def secure_admin_audit(request: Request) -> dict[str, Any]:
    identity = secure_identity(request)
    if identity.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    return {"audit": "synthetic-admin-log", "user_count": len(USERS)}


@app.get("/vuln/profiles/{user_id}", tags=["vulnerable"])
def vulnerable_profile(user_id: str, request: Request) -> dict[str, Any]:
    vulnerable_identity(request)
    return _user_or_404(user_id)["profile"]


@app.patch("/vuln/profiles/{user_id}", tags=["vulnerable"])
def vulnerable_profile_update(
    user_id: str, update: ProfileUpdate, request: Request
) -> dict[str, Any]:
    vulnerable_identity(request)
    user = _user_or_404(user_id)
    for key, value in update.model_dump(exclude_none=True).items():
        if key == "role":
            user["role"] = value
        else:
            user["profile"][key] = value
    return user


@app.get("/secure/profiles/{user_id}", tags=["secure"])
def secure_profile(user_id: str, request: Request) -> dict[str, str]:
    identity = secure_identity(request)
    if identity["sub"] != user_id and identity.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="object ownership required"
        )
    return _public_profile(_user_or_404(user_id))


@app.patch("/secure/profiles/{user_id}", tags=["secure"])
def secure_profile_update(user_id: str, update: ProfileUpdate, request: Request) -> dict[str, str]:
    identity = secure_identity(request)
    if identity["sub"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="object ownership required"
        )
    user = _user_or_404(user_id)
    if update.display_name is not None:
        user["profile"]["display_name"] = update.display_name
    return _public_profile(user)


@app.get("/vuln/payments/{user_id}", tags=["vulnerable"])
def vulnerable_payment(user_id: str, request: Request) -> dict[str, Any]:
    vulnerable_identity(request)
    return _user_or_404(user_id)["payment"]


@app.get("/secure/payments/{user_id}", tags=["secure"])
def secure_payment(user_id: str, request: Request) -> dict[str, str]:
    identity = secure_identity(request)
    if identity["sub"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="payment ownership required"
        )
    payment = _user_or_404(user_id)["payment"]
    return {"account_ref": payment["account_ref"]}


@app.get("/vuln/orders/{order_id}", tags=["vulnerable"])
def vulnerable_order(order_id: str, request: Request) -> dict[str, Any]:
    vulnerable_identity(request)
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="synthetic order not found"
        )
    return order


@app.get("/secure/orders/{order_id}", tags=["secure"])
def secure_order(order_id: str, request: Request) -> dict[str, Any]:
    identity = secure_identity(request)
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="synthetic order not found"
        )
    if order["owner_id"] != identity["sub"] and identity.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="order ownership required"
        )
    return order


@app.get("/v1/users/{user_id}", deprecated=True, tags=["deprecated"])
def deprecated_v1_user(user_id: str) -> dict[str, str]:
    return _public_profile(_user_or_404(user_id))


@app.get("/internal/diagnostics", include_in_schema=False, tags=["shadow"])
def undocumented_internal_diagnostics() -> dict[str, str]:
    return {"component": "synthetic-lab", "diagnostic": "shadow-endpoint"}


_query = GraphQLObjectType(
    "Query",
    lambda: {
        "labStatus": GraphQLField(GraphQLString, resolve=lambda *_: "synthetic-lab-ready"),
        "userEmail": GraphQLField(
            GraphQLString,
            args={},
            resolve=lambda *_: USERS["alice"]["email"],
        ),
    },
)
GRAPHQL_SCHEMA = GraphQLSchema(query=_query)


@app.post("/vuln/graphql", tags=["vulnerable"])
def vulnerable_graphql(payload: GraphQLRequest) -> dict[str, Any]:
    result = graphql_sync(GRAPHQL_SCHEMA, payload.query)
    return {"data": result.data, "errors": [str(error) for error in result.errors or []]}


@app.post("/secure/graphql", tags=["secure"])
def secure_graphql(payload: GraphQLRequest) -> dict[str, Any]:
    if "__schema" in payload.query or "__type" in payload.query:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="introspection disabled")
    result = graphql_sync(GRAPHQL_SCHEMA, payload.query)
    return {"data": result.data, "errors": [str(error) for error in result.errors or []]}
