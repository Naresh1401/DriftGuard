"""Domain configuration API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel

from api.middleware.auth import get_current_user
from models import User

router = APIRouter(prefix="/domains", tags=["Domains"])


@router.get("")
async def list_domains(user: User = Depends(get_current_user)):
    """List all available domain configurations."""
    from main import app_state
    return {"domains": app_state.domain_registry.list_domains()}


@router.get("/{domain_name}")
async def get_domain(domain_name: str, user: User = Depends(get_current_user)):
    """Get a specific domain configuration."""
    from main import app_state
    config = app_state.domain_registry.get_domain(domain_name)
    if not config:
        raise HTTPException(status_code=404, detail=f"Domain '{domain_name}' not found")
    return config.to_dict()


@router.post("/upload")
async def upload_domain_config(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
):
    """Upload a custom YAML domain configuration."""
    from main import app_state

    if not file.filename or not file.filename.endswith((".yaml", ".yml")):
        raise HTTPException(status_code=400, detail="File must be a YAML file")

    content = await file.read()
    yaml_string = content.decode("utf-8")

    config = app_state.domain_registry.load_config_string(yaml_string)
    if not config:
        raise HTTPException(status_code=400, detail="Invalid YAML domain configuration")

    return {
        "status": "uploaded",
        "domain": config.domain,
        "display_name": config.display_name,
        "signal_count": len(config.signals),
    }


class YamlConfigInput(BaseModel):
    yaml_content: str


@router.post("/upload/yaml")
async def upload_yaml_string(
    input: YamlConfigInput,
    user: User = Depends(get_current_user),
):
    """Upload a YAML domain configuration as a string."""
    from main import app_state

    config = app_state.domain_registry.load_config_string(input.yaml_content)
    if not config:
        raise HTTPException(status_code=400, detail="Invalid YAML configuration")

    return {
        "status": "uploaded",
        "domain": config.domain,
        "signals": [s.to_dict() for s in config.signals],
    }
