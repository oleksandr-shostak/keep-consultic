import enum
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import BOOLEAN, TEXT, Column, Index, UniqueConstraint, false
from sqlalchemy_utils import UUIDType
from sqlmodel import JSON, Field, SQLModel

from keep.api.models.db.helpers import DATETIME_COLUMN_TYPE


class IncidentSeverityProposalStatus(str, enum.Enum):
    PENDING = "pending"
    SYNCED = "synced"
    FAILED = "failed"


class IncidentSeverityProposal(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(foreign_key="tenant.id", index=True)
    incident_id: UUID = Field(
        sa_column=Column(UUIDType(binary=False), nullable=False),
    )
    current_severity: str = Field(index=True)
    proposed_severity: str = Field(index=True)
    reason: str = Field(sa_column=Column(TEXT, nullable=False))
    incident_name: str = Field(sa_column=Column(TEXT, nullable=False))
    incident_status: str = Field(index=True)
    incident_snapshot: dict = Field(default_factory=dict, sa_column=Column(JSON))
    alerts_count: int = Field(default=0)
    alerts_snapshot: list = Field(default_factory=list, sa_column=Column(JSON))
    created_by: str = Field(index=True)
    created_at: datetime = Field(
        sa_column=Column(DATETIME_COLUMN_TYPE, nullable=False),
        default_factory=lambda: datetime.now(tz=timezone.utc),
    )
    idempotency_key: str | None = Field(default=None, index=True)
    dedupe_hash: str = Field(index=True)
    sync_status: str = Field(
        default=IncidentSeverityProposalStatus.PENDING.value,
        index=True,
    )
    sync_status_reason: str | None = Field(default=None, sa_column=Column(TEXT))
    sync_attempts: int = Field(default=0)
    last_synced_at: datetime | None = Field(
        default=None, sa_column=Column(DATETIME_COLUMN_TYPE, nullable=True)
    )
    updated_by: str | None = Field(default=None, index=True)
    updated_at: datetime | None = Field(
        default=None, sa_column=Column(DATETIME_COLUMN_TYPE, nullable=True)
    )
    is_deleted: bool = Field(
        default=False,
        sa_column=Column(BOOLEAN, nullable=False, server_default=false()),
    )
    deleted_by: str | None = Field(default=None, index=True)
    deleted_at: datetime | None = Field(
        default=None, sa_column=Column(DATETIME_COLUMN_TYPE, nullable=True)
    )
    openai_file_id: str | None = Field(default=None, index=True)
    openai_vector_file_id: str | None = Field(default=None, index=True)
    vector_store_id: str | None = Field(default=None)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "dedupe_hash",
            name="uq_incidentseverityproposal_tenant_dedupe_hash",
        ),
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_incidentseverityproposal_tenant_idempotency_key",
        ),
        Index(
            "idx_incidentseverityproposal_tenant_status",
            "tenant_id",
            "sync_status",
        ),
        Index(
            "idx_incidentseverityproposal_tenant_created_at",
            "tenant_id",
            "created_at",
        ),
        Index(
            "idx_incidentseverityproposal_tenant_incident_deleted",
            "tenant_id",
            "incident_id",
            "is_deleted",
        ),
    )
