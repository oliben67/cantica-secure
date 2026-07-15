"""Directory group → role mapping endpoints (spec REGISTRATION B.pre).

Admin CRUD for the directory_group_roles table: which external directory
groups (AD DNs, OIDC groups-claim values) grant which Studio roles.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from cantica_secure.api.deps import CurrentUserDep, DbSession, require_permission
from cantica_secure.core.flags import audit_log
from cantica_secure.orm.models import DirectoryGroupRole, Role

router = APIRouter()


class CreateMappingRequest(BaseModel):
    external_group: str
    role_name: str


def _mapping_dict(m: DirectoryGroupRole) -> dict:
    return {
        "id": m.id,
        "external_group": m.external_group,
        "role": m.role.name,
        "created_at": m.created_at.isoformat(),
    }


@router.get("/mappings", dependencies=[require_permission("roles:read")])
def list_mappings(db: DbSession) -> list[dict]:
    mappings = db.scalars(
        select(DirectoryGroupRole).options(selectinload(DirectoryGroupRole.role))
    ).all()
    return [_mapping_dict(m) for m in mappings]


@router.post("/mappings", status_code=201, dependencies=[require_permission("roles:write")])
def create_mapping(body: CreateMappingRequest, current_user: CurrentUserDep, db: DbSession) -> dict:
    external_group = body.external_group.strip()
    if not external_group:
        raise HTTPException(status_code=422, detail="external_group is required")
    role = db.scalar(select(Role).where(Role.name == body.role_name))
    if role is None:
        raise HTTPException(status_code=404, detail=f"Role {body.role_name!r} not found")
    duplicate = db.scalar(
        select(DirectoryGroupRole).where(
            DirectoryGroupRole.external_group == external_group,
            DirectoryGroupRole.role_id == role.id,
        )
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="Mapping already exists")

    m = DirectoryGroupRole(external_group=external_group, role_id=role.id)
    db.add(m)
    db.commit()
    db.refresh(m)
    audit_log.info(
        "directory mapping added: %r -> %s by=%s", external_group, role.name, current_user.user_id
    )
    return _mapping_dict(m)


@router.delete("/mappings/{mapping_id}", status_code=204, dependencies=[require_permission("roles:write")])
def delete_mapping(mapping_id: str, current_user: CurrentUserDep, db: DbSession) -> None:
    m = db.scalar(select(DirectoryGroupRole).where(DirectoryGroupRole.id == mapping_id))
    if m is None:
        raise HTTPException(status_code=404, detail="Mapping not found")
    db.delete(m)
    db.commit()
    audit_log.info("directory mapping removed: %s by=%s", mapping_id, current_user.user_id)
