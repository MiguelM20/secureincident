"""Strict job input, with no client-controlled identity or scopes."""

from pydantic import BaseModel, ConfigDict, Field


class ReportJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: int = Field(ge=1)
    read_grant: str = Field(min_length=20, max_length=8192)
    write_grant: str = Field(min_length=20, max_length=8192)
    filename: str | None = Field(default=None, min_length=5, max_length=84)
