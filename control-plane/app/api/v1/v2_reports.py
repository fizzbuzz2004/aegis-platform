from __future__ import annotations

import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.v2_database import (
    VerifiedTenantContext,
    get_v2_session,
    get_verified_tenant_context,
)
from app.models.v2 import OutboxEvent, ReportJob, ScanRun

router = APIRouter()
logger = logging.getLogger(__name__)


class ReportJobRequest(BaseModel):
    snapshot_id: UUID


class ReportJobResponse(BaseModel):
    job_id: UUID
    status: str
    status_url: str
    download_url: str | None = None


@router.post("/reports", response_model=ReportJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_report_job(
    payload: ReportJobRequest,
    context: VerifiedTenantContext = Depends(get_verified_tenant_context),
    session: AsyncSession = Depends(get_v2_session),
):
    """Nimmt einen Report-Erstellungsauftrag an, prüft den Scan-Snapshot und stellt diesen in die Outbox."""
    if context.customer_id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A customer scope is required")
    
    snapshot = await session.scalar(
        select(ScanRun).where(
            ScanRun.id == payload.snapshot_id,
            ScanRun.msp_id == context.msp_id,
            ScanRun.customer_id == context.customer_id,
        )
    )
    if snapshot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan snapshot not found")
    if snapshot.status != "complete" or not snapshot.evaluated_at or not snapshot.data_as_of:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan snapshot is not finalized")

    job_id = uuid4()
    session.add(ReportJob(
        id=job_id,
        msp_id=context.msp_id,
        customer_id=context.customer_id,
        requested_by=context.user_id,
        snapshot_id=snapshot.id,
        evaluated_at=snapshot.evaluated_at,
        data_as_of=snapshot.data_as_of,
        rule_pack_digest=snapshot.rule_pack_digest,
        status="queued",
    ))
    session.add(OutboxEvent(
        id=uuid4(),
        msp_id=context.msp_id,
        customer_id=context.customer_id,
        aggregate_type="report_job",
        aggregate_id=job_id,
        event_type="report.generate.requested",
        payload={"job_id": str(job_id), "snapshot_id": str(snapshot.id)},
    ))
    await session.flush()
    logger.info(f"Asynchroner Report-Job {job_id} erfolgreich für Snapshot {snapshot.id} in Outbox eingereiht.")
    
    return ReportJobResponse(
        job_id=job_id,
        status="queued",
        status_url=f"/api/v2/reports/{job_id}",
    )


@router.get("/reports/{job_id}", response_model=ReportJobResponse)
async def get_report_job(
    job_id: UUID,
    context: VerifiedTenantContext = Depends(get_verified_tenant_context),
    session: AsyncSession = Depends(get_v2_session),
):
    """Liefert den Status des Report-Jobs und generiert bei Fertigstellung eine temporäre S3 Presigned URL."""
    job = await session.scalar(
        select(ReportJob).where(
            ReportJob.id == job_id,
            ReportJob.msp_id == context.msp_id,
            ReportJob.customer_id == context.customer_id,
        )
    )
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report job not found")

    download_url = None
    if job.status == "complete":
        if not settings.EVIDENCE_BUCKET or not job.object_key:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Report object storage is not configured")
        import boto3

        storage = boto3.client("s3", region_name=settings.AWS_REGION)
        # Generiere eine sichere, kurzlebige Presigned URL (15 Minuten gültig)
        download_url = storage.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.EVIDENCE_BUCKET, "Key": job.object_key},
            ExpiresIn=900,
        )
        
    return ReportJobResponse(
        job_id=job.id,
        status=job.status,
        status_url=f"/api/v2/reports/{job.id}",
        download_url=download_url,
    )
