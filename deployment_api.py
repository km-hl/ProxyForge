"""Management-only desired state. No private keys accepted or returned."""
from fastapi.responses import JSONResponse
from typing import Literal
from pydantic import Field, StrictInt, StrictBool, model_validator
from agent_api import Payload, Identifier
from agent.deployment_spec import validate_settings
from agent.landing_spec import validate_settings as validate_landing_settings
from deployment_store import DeploymentKeyError
from agent.chain_spec import validate_settings as validate_chain_settings


class ChainRequest(Payload):
    request_id: Identifier
    expected_revision: StrictInt = Field(ge=0, le=2147483646)
    landing_agent_id: Identifier
    settings: dict
    remove: StrictBool = False

    @model_validator(mode='after')
    def settings_schema(self):
        validate_chain_settings(self.settings)
        return self


class DeploymentRequest(Payload):
    request_id: Identifier
    expected_revision: StrictInt = Field(ge=0, le=2147483646)
    settings: dict
    remove: StrictBool = False
    protocol: Literal['vless-reality', 'ss2022'] = 'vless-reality'

    @model_validator(mode='after')
    def settings_schema(self):
        (validate_landing_settings if self.protocol == 'ss2022' else validate_settings)(self.settings)
        return self


def attach_deployment_routes(app, admin, store_provider):
    @admin.get('/deployments/landings')
    def chain_landings():
        return {'landings': store_provider().chain_landings()}

    @admin.get('/{agent_id}/chain')
    def get_chain(agent_id: str):
        return {'chain': store_provider().get_chain(agent_id)}

    @admin.put('/{agent_id}/chain')
    def put_chain(agent_id: str, data: ChainRequest):
        return store_provider().put_chain(agent_id, data.request_id, data.expected_revision,
                                         data.landing_agent_id, data.settings, data.remove)

    @app.exception_handler(DeploymentKeyError)
    async def unavailable(request, exc):
        return JSONResponse({'detail': 'Deployment key unavailable; restore the matching private backup'}, status_code=503)

    @admin.get('/{agent_id}/deployment')
    def get_deployment(agent_id: str):
        return {'deployment': store_provider().get_deployment(agent_id)}

    @admin.put('/{agent_id}/deployment')
    def put_deployment(agent_id: str, data: DeploymentRequest):
        return store_provider().put_deployment(agent_id, data.request_id, data.expected_revision, data.settings, data.remove, data.protocol)
