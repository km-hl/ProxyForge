"""Management-only desired state and non-secret key helper endpoints."""
from typing import Literal, Optional

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import Field, StrictBool, StrictInt, constr, model_validator

from agent.chain_spec import validate_settings as validate_chain_settings
from agent.deployment_spec import validate_settings
from agent.landing_spec import PROTOCOL_SPEC, validate_settings as validate_landing_settings
from proxyforge.control.agent_api import Identifier, Payload
from proxyforge.control.deployment_store import DeploymentKeyError, DeploymentValidationError


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
    protocol: Literal['vless-reality', 'ss2022', 'reality', 'trojan', 'anytls', 'vless-ws', 'hysteria2'] = 'vless-reality'
    secrets: Optional[dict] = None
    key_ref: Optional[constr(strict=True, min_length=16, max_length=4096)] = None

    @model_validator(mode='after')
    def settings_schema(self):
        if self.protocol == 'vless-reality':
            if self.secrets is not None or self.key_ref is not None:
                raise ValueError('Legacy vless-reality does not accept landing secrets or key_ref')
            validate_settings(self.settings)
        else:
            validate_landing_settings(self.settings, protocol=self.protocol)
            if self.secrets is not None:
                if not isinstance(self.secrets, dict) or set(self.secrets) - {'dns_api_token', 'outbound_password', 'hop_passwords'}:
                    raise ValueError('Unsupported deployment secrets field')
                token = self.secrets.get('dns_api_token')
                if token is not None and (not isinstance(token, str) or not 12 <= len(token) <= 256 or any(ord(c) < 32 for c in token)):
                    raise ValueError('Invalid ACME DNS API token')
                out_pw = self.secrets.get('outbound_password')
                if out_pw is not None and (not isinstance(out_pw, str) or not 1 <= len(out_pw) <= 256 or any(ord(c) < 32 for c in out_pw)):
                    raise ValueError('Invalid outbound password')
                hop_pws = self.secrets.get('hop_passwords')
                if hop_pws is not None:
                    if not isinstance(hop_pws, dict) or len(hop_pws) > 4:
                        raise ValueError('Invalid hop_passwords')
                    for k, v in hop_pws.items():
                        if k not in ('0', '1', '2', '3') or not isinstance(v, str) or len(v) > 256 or any(ord(c) < 32 for c in v):
                            raise ValueError('Invalid hop_passwords entry')
        return self


class AgentNodeUpsertRequest(Payload):
    request_id: Identifier
    protocol: Literal['ss2022', 'reality', 'trojan', 'anytls', 'vless-ws', 'hysteria2'] = 'reality'
    settings: dict
    secrets: Optional[dict] = None
    key_ref: Optional[constr(strict=True, min_length=16, max_length=4096)] = None


class AgentNodeDeleteRequest(Payload):
    request_id: Identifier


class LandingKeyHelperRequest(Payload):
    protocol: Literal['ss2022', 'reality', 'trojan', 'anytls', 'vless-ws', 'hysteria2'] = 'reality'


def attach_deployment_routes(app, admin, store_provider, *, rename_template_references=None):
    @admin.get('/managed/nodes')
    def managed_nodes(include_discovered: bool = False):
        return {'nodes': store_provider().managed_inventory(include_discovered=include_discovered)}

    @admin.get('/deployments/landings')
    def chain_landings():
        return {'landings': store_provider().chain_landings()}

    @admin.get('/deployments/ss-landings')
    def list_ss_landings():
        return {'landings': store_provider().list_ss_landings()}

    @admin.get('/deployments/overview')
    def agents_overview():
        return {'agents': store_provider().agents_overview()}

    @admin.post('/deployments/generate-keys')
    def generate_landing_keys(data: LandingKeyHelperRequest):
        return store_provider().generate_landing_keys(protocol=data.protocol)

    @admin.get('/deployments/protocols')
    def landing_protocols():
        return {
            'protocols': {
                name: {
                    'tls_modes': list(spec['tls_modes']),
                    'default_tls_mode': spec['default_tls'],
                    'requires_domain': spec['requires_domain'],
                    'project_client': spec['project_client'],
                }
                for name, spec in PROTOCOL_SPEC.items()
            }
        }

    @admin.get('/{agent_id}/chain')
    def get_chain(agent_id: str):
        return {'chain': store_provider().get_chain(agent_id)}

    @admin.put('/{agent_id}/chain')
    def put_chain(agent_id: str, data: ChainRequest):
        return store_provider().put_chain(
            agent_id, data.request_id, data.expected_revision,
            data.landing_agent_id, data.settings, data.remove,
        )

    @app.exception_handler(DeploymentKeyError)
    async def unavailable(request, exc):
        return JSONResponse({'detail': 'Deployment key unavailable; restore the matching private backup'}, status_code=503)

    @admin.get('/{agent_id}/deployment')
    def get_deployment(agent_id: str):
        return {'deployment': store_provider().get_deployment(agent_id)}

    @admin.put('/{agent_id}/deployment')
    def put_deployment(agent_id: str, data: DeploymentRequest):
        try:
            return store_provider().put_deployment(
                agent_id,
                data.request_id,
                data.expected_revision,
                data.settings,
                data.remove,
                data.protocol,
                secrets_input=data.secrets,
                key_ref=data.key_ref,
            )
        except DeploymentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except ValueError:
            # Never echo user-provided secrets or detailed validation strings.
            raise HTTPException(status_code=422, detail='Invalid deployment specification') from None

    @admin.get('/{agent_id}/nodes')
    def list_agent_nodes(agent_id: str):
        store = store_provider()
        try:
            agent = store.get_agent(agent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail='Agent not found') from None
        return {
            'nodes': store.list_agent_nodes(agent_id),
            'public_ipv4': agent.get('public_ipv4', ''),
            'public_ipv6': agent.get('public_ipv6', ''),
        }

    @admin.post('/{agent_id}/nodes')
    def create_agent_node(agent_id: str, data: AgentNodeUpsertRequest):
        try:
            result = store_provider().upsert_agent_node(
                agent_id,
                data.request_id,
                data.protocol,
                data.settings,
                secrets_input=data.secrets,
                key_ref=data.key_ref,
            )
            if (isinstance(result, dict) and result.get('renamed_from') and result.get('renamed_to')
                    and callable(rename_template_references)):
                try:
                    result['template_migrated'] = rename_template_references(result['renamed_from'], result['renamed_to'])
                except Exception:
                    pass
            return result
        except DeploymentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except ValueError:
            raise HTTPException(status_code=422, detail='Invalid deployment specification') from None

    @admin.put('/{agent_id}/nodes/{node_id}')
    def update_agent_node(agent_id: str, node_id: str, data: AgentNodeUpsertRequest):
        try:
            result = store_provider().upsert_agent_node(
                agent_id,
                data.request_id,
                data.protocol,
                data.settings,
                node_id=node_id,
                secrets_input=data.secrets,
                key_ref=data.key_ref,
            )
            if (isinstance(result, dict) and result.get('renamed_from') and result.get('renamed_to')
                    and callable(rename_template_references)):
                try:
                    result['template_migrated'] = rename_template_references(result['renamed_from'], result['renamed_to'])
                except Exception:
                    pass
            return result
        except DeploymentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except ValueError:
            raise HTTPException(status_code=422, detail='Invalid deployment specification') from None

    @admin.delete('/{agent_id}/nodes/{node_id}')
    def delete_agent_node(agent_id: str, node_id: str, data: AgentNodeDeleteRequest):
        try:
            return store_provider().delete_agent_node(agent_id, node_id, data.request_id)
        except DeploymentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except ValueError:
            raise HTTPException(status_code=422, detail='Invalid deployment specification') from None
