"""Validate the user-facing JSON boundary before forwarding to Incident Service."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "investigating", "resolved"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Credentials(StrictModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=1024)


class IncidentCreate(StrictModel):
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=1, max_length=4000)
    severity: Severity


class IncidentUpdate(StrictModel):
    description: str | None = Field(default=None, min_length=1, max_length=4000)
    severity: Severity | None = None
    status: IncidentStatus | None = None

    @model_validator(mode="after")
    def nonempty(self) -> "IncidentUpdate":
        values = self.model_dump(exclude_unset=True)
        if not values or any(value is None for value in values.values()):
            raise ValueError("Provide at least one non-null update field")
        return self


class IncidentAssign(StrictModel):
    owner_id: int = Field(ge=1)
