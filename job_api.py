"""No arbitrary command, path, URL or deployment payload is accepted by B2."""
from typing import Literal, Optional

from fastapi import Header
from fastapi.responses import JSONResponse
from pydantic import Field, constr, model_validator

from agent_api import Payload, Identifier, SingboxStatus
from control_store import UnauthorizedAgent
from job_store import JobConflict, JobNotFound


class JobRequest(Payload):
    request_id: Identifier
    type: Literal['singbox.status']
    payload: Payload = Field(default_factory=Payload)
    deployment_revision: None = None


class ClaimRequest(Payload):
    instance_id: Identifier


class LeaseRequest(Payload):
    lease_token: constr(strict=True, pattern=r'^[A-Za-z0-9_-]{43}$')


class StatusOutput(SingboxStatus):
    status: Literal['not_installed', 'running', 'stopped', 'unknown']


class JobResult(Payload):
    status: Literal['success', 'failed']
    output: Optional[StatusOutput] = None
    error: Optional[Literal['probe_failed']] = None

    @model_validator(mode='after')
    def coherent(self):
        if self.status == 'success' and (self.output is None or self.error is not None):
            raise ValueError('Success requires output only')
        if self.status == 'failed' and (self.output is not None or self.error is None):
            raise ValueError('Failure requires error only')
        return self


class ResultRequest(LeaseRequest):
    result: JobResult


def attach_job_routes(app, admin, agent, store_provider):
    def credential(authorization):
        if not authorization.startswith('Bearer ') or len(authorization) > 160:
            raise UnauthorizedAgent()
        return authorization[7:]

    @app.exception_handler(JobConflict)
    async def conflict(request, exc):
        return JSONResponse({'detail': 'Job lease, state or Agent capability changed'}, status_code=409)

    @app.exception_handler(JobNotFound)
    async def not_found(request, exc):
        return JSONResponse({'detail': 'Job or Agent not found'}, status_code=404)

    @admin.post('/{agent_id}/jobs')
    def create_job(agent_id: str, data: JobRequest):
        return store_provider().create_job(agent_id, data.request_id)

    @admin.get('/{agent_id}/jobs')
    def list_jobs(agent_id: str):
        return {'jobs': store_provider().list_jobs(agent_id)}

    @admin.post('/{agent_id}/jobs/{job_id}/cancel')
    def cancel_job(agent_id: str, job_id: str):
        return store_provider().cancel_job(agent_id, job_id)

    @agent.post('/jobs/claim')
    def claim_job(data: ClaimRequest, authorization: str = Header(default='')):
        return {'job': store_provider().claim_job(credential(authorization), data.instance_id)}

    @agent.post('/jobs/{job_id}/start')
    def start_job(job_id: str, data: LeaseRequest, authorization: str = Header(default='')):
        return store_provider().report_job(credential(authorization), job_id, data.lease_token)

    @agent.post('/jobs/{job_id}/result')
    def result_job(job_id: str, data: ResultRequest, authorization: str = Header(default='')):
        return store_provider().report_job(credential(authorization), job_id, data.lease_token,
                                           data.result.model_dump())
