"""Main API router combining versioned sub-routers."""

from fastapi import APIRouter

from app.api.v1.actions import router as actions_router
from app.api.v1.health import router as health_router
from app.api.v1.intents import router as intents_router

api_router = APIRouter()
api_router.include_router(health_router, prefix="/v1")
api_router.include_router(actions_router, prefix="/v1")
api_router.include_router(intents_router, prefix="/v1")
