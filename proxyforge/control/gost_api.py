"""Control-plane HTTP APIs for go-gost forwards, multi-hop chains, Best Exit, and byte counters."""
from typing import Literal, Optional, Union

from fastapi import Header, HTTPException
from pydantic import Field, StrictBool, StrictFloat, StrictInt, constr, model_validator

from agent.gost_manager import (
    CONNECTOR_TYPES,
    DIALER_TYPES,
    FORWARD_PROTOCOLS,
    SELECTOR_STRATEGIES,
    validate_host_port,
)
from proxyforge.control.agent_api import Identifier, Payload, ShortText


class ForwardTargetItem(Payload):
    addr: constr(strict=True, min_length=3, max_length=260)
    name: ShortText = ''
    chain: constr(strict=True, max_length=64) = ''

    @model_validator(mode='after')
    def check_addr(self):
        validate_host_port(self.addr, 'target addr')
        return self


class ForwardCreateRequest(Payload):
    request_id: Identifier
    name: constr(strict=True, min_length=1, max_length=128)
    listen: ShortText = '::'
    listen_port: StrictInt = Field(ge=1, le=65535)
    protocol: Literal['tcp', 'udp', 'tcp+udp'] = 'tcp+udp'
    mode: Literal['direct', 'chain', 'best_exit'] = 'direct'
    chain_id: constr(strict=True, max_length=64) = ''
    exit_group_id: constr(strict=True, max_length=64) = ''
    targets: list[ForwardTargetItem] = Field(default_factory=list, max_length=16)
    strategy: Literal['fifo', 'round', 'random'] = 'fifo'
    max_fails: StrictInt = Field(default=1, ge=1, le=10)
    fail_timeout: StrictInt = Field(default=10, ge=1, le=300)
    proxy_protocol: StrictInt = Field(default=0, ge=0, le=2)
    interface: constr(strict=True, max_length=32) = ''
    enabled: StrictBool = True
    rewrite_subscription: StrictBool = False

    @model_validator(mode='after')
    def validate_mode(self):
        if self.mode == 'best_exit':
            if not self.exit_group_id:
                raise ValueError('best_exit mode requires exit_group_id')
        else:
            if not self.targets:
                raise ValueError('At least one forward target is required')
        if self.mode == 'chain' and not self.chain_id:
            raise ValueError('chain mode requires chain_id')
        if self.protocol not in FORWARD_PROTOCOLS or self.strategy not in SELECTOR_STRATEGIES:
            raise ValueError('Invalid forward options')
        return self


class ForwardToggleRequest(Payload):
    request_id: Identifier
    enabled: StrictBool


class ForwardSubscriptionRequest(Payload):
    rewrite_subscription: StrictBool


class ForwardDeleteRequest(Payload):
    request_id: Identifier


class HopNodeRequest(Payload):
    name: constr(strict=True, min_length=1, max_length=64, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
    addr: constr(strict=True, min_length=3, max_length=260)
    connector: Literal['relay', 'socks5', 'http', 'ss', 'direct'] = 'relay'
    dialer: Literal['tcp', 'tls', 'mtls', 'ws', 'wss', 'kcp', 'quic'] = 'tls'
    username: constr(strict=True, max_length=128) = ''
    password: constr(strict=True, max_length=256) = ''
    server_name: constr(strict=True, max_length=253) = ''
    insecure: StrictBool = False
    nodelay: StrictBool = True
    interface: constr(strict=True, max_length=32) = ''
    agent_id: Optional[Identifier] = None
    listen: ShortText = '::'
    serve_on_agent: StrictBool = False

    @model_validator(mode='after')
    def check_node(self):
        validate_host_port(self.addr, 'hop node addr')
        if self.connector not in CONNECTOR_TYPES or self.dialer not in DIALER_TYPES:
            raise ValueError('Unsupported connector or dialer')
        if self.serve_on_agent and not self.agent_id:
            raise ValueError('serve_on_agent requires agent_id')
        return self


class HopRequest(Payload):
    name: constr(strict=True, min_length=1, max_length=64, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
    interface: constr(strict=True, max_length=32) = ''
    strategy: Literal['fifo', 'round', 'random'] = 'fifo'
    max_fails: StrictInt = Field(default=1, ge=1, le=10)
    fail_timeout: StrictInt = Field(default=10, ge=1, le=300)
    nodes: list[HopNodeRequest] = Field(min_length=1, max_length=16)


class TunnelChainCreateRequest(Payload):
    request_id: Identifier
    name: constr(strict=True, min_length=1, max_length=64, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
    entry_agent_id: Identifier
    hops: list[HopRequest] = Field(min_length=1, max_length=8)


class BestExitNodeRequest(Payload):
    id: constr(strict=True, min_length=1, max_length=64, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
    name: constr(strict=True, max_length=64) = ''
    addr: constr(strict=True, min_length=3, max_length=260)
    chain: constr(strict=True, max_length=64) = ''
    probe_host: constr(strict=True, max_length=253) = ''
    probe_port: StrictInt = Field(default=0, ge=0, le=65535)
    target_host: constr(strict=True, max_length=253) = ''
    target_port: StrictInt = Field(default=0, ge=0, le=65535)
    weight: StrictInt = Field(default=100, ge=1, le=10000)

    @model_validator(mode='after')
    def check_exit(self):
        validate_host_port(self.addr, 'exit addr')
        return self


class BestExitGroupCreateRequest(Payload):
    request_id: Identifier
    name: constr(strict=True, min_length=1, max_length=64, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
    probe_interval: StrictInt = Field(default=15, ge=5, le=300)
    confirmation_rounds: StrictInt = Field(default=3, ge=1, le=10)
    cooldown_seconds: StrictInt = Field(default=30, ge=0, le=600)
    min_advantage_ms: Union[StrictFloat, StrictInt] = Field(default=20.0, ge=0, le=10000)
    min_advantage_ratio: Union[StrictFloat, StrictInt] = Field(default=0.15, ge=0, le=1)
    selected_exit_id: constr(strict=True, max_length=64) = ''
    exits: list[BestExitNodeRequest] = Field(min_length=1, max_length=16)


class ExitProbeSample(Payload):
    entry_latency_ms: Union[StrictFloat, StrictInt] = Field(default=0.0, ge=0, le=60000)
    entry_loss_pct: Union[StrictFloat, StrictInt] = Field(default=0.0, ge=0, le=100)
    exit_latency_ms: Union[StrictFloat, StrictInt] = Field(default=0.0, ge=0, le=60000)
    exit_loss_pct: Union[StrictFloat, StrictInt] = Field(default=0.0, ge=0, le=100)


class BestExitEvaluateRequest(Payload):
    request_id: Optional[Identifier] = None
    probes: dict[constr(strict=True, min_length=1, max_length=64), ExitProbeSample] = Field(max_length=16)


class TrafficCounterItem(Payload):
    resource_key: constr(strict=True, min_length=1, max_length=128)
    forward_rule_id: constr(strict=True, max_length=64) = ''
    rx_delta: StrictInt = Field(ge=0)
    tx_delta: StrictInt = Field(ge=0)
    raw_rx: StrictInt = Field(ge=0)
    raw_tx: StrictInt = Field(ge=0)
    epoch: constr(strict=True, max_length=64) = ''


class TrafficUploadRequest(Payload):
    instance_id: Identifier
    batch_id: Identifier
    sequence: StrictInt = Field(ge=0)
    items: list[TrafficCounterItem] = Field(default_factory=list, max_length=64)


class AgentBestExitReport(Payload):
    instance_id: Identifier
    group_id: Identifier
    probes: dict[constr(strict=True, min_length=1, max_length=64), ExitProbeSample] = Field(max_length=16)


def attach_gost_routes(admin, agent, store_provider):
    @admin.get('/forwards/relays')
    def list_relays():
        return {'relays': store_provider().list_active_relays()}

    @admin.get('/tunnels/chains')
    def list_chains():
        return {'chains': store_provider().list_tunnel_chains()}

    @admin.post('/tunnels/chains')
    def create_chain(data: TunnelChainCreateRequest):
        hops_raw = [h.model_dump() for h in data.hops]
        try:
            return store_provider().create_tunnel_chain(data.request_id, data.name, data.entry_agent_id, hops_raw)
        except ValueError:
            raise HTTPException(status_code=422, detail='Invalid tunnel chain specification') from None

    @admin.delete('/tunnels/chains/{chain_id}')
    def delete_chain(chain_id: str, request_id: Identifier):
        return store_provider().delete_tunnel_chain(chain_id, request_id)

    @admin.get('/traffic/summary')
    def traffic_summary():
        return store_provider().traffic_summary()

    @admin.get('/{agent_id}/forwards')
    def list_agent_forwards(agent_id: str):
        return {'forwards': store_provider().list_forwards(agent_id)}

    @admin.post('/{agent_id}/forwards')
    def create_agent_forward(agent_id: str, data: ForwardCreateRequest):
        try:
            return store_provider().create_forward(agent_id, data.request_id, data.model_dump(exclude={'request_id'}))
        except ValueError:
            raise HTTPException(status_code=422, detail='Invalid forward rule specification') from None

    @admin.post('/{agent_id}/forwards/{rule_id}/toggle')
    def toggle_agent_forward(agent_id: str, rule_id: str, data: ForwardToggleRequest):
        return store_provider().set_forward_enabled(rule_id, data.enabled, data.request_id, agent_id=agent_id)

    @admin.post('/{agent_id}/forwards/{rule_id}/subscription')
    def toggle_agent_forward_subscription(agent_id: str, rule_id: str, data: ForwardSubscriptionRequest):
        return store_provider().set_forward_rewrite_subscription(
            rule_id, data.rewrite_subscription, agent_id=agent_id,
        )

    @admin.delete('/{agent_id}/forwards/{rule_id}')
    def delete_agent_forward(agent_id: str, rule_id: str, request_id: Identifier):
        return store_provider().delete_forward(agent_id, rule_id, request_id)

    @admin.get('/{agent_id}/best-exits')
    def list_agent_best_exits(agent_id: str):
        return {'groups': store_provider().list_best_exit_groups(agent_id)}

    @admin.post('/{agent_id}/best-exits')
    def create_agent_best_exit(agent_id: str, data: BestExitGroupCreateRequest):
        try:
            return store_provider().create_best_exit_group(
                agent_id, data.request_id, data.model_dump(exclude={'request_id'}),
            )
        except ValueError:
            raise HTTPException(status_code=422, detail='Invalid Best Exit group specification') from None

    @admin.post('/best-exits/{group_id}/evaluate')
    def evaluate_best_exit(group_id: str, data: BestExitEvaluateRequest):
        probes = {eid: sample.model_dump() for eid, sample in data.probes.items()}
        return store_provider().evaluate_best_exit_group(group_id, probes, request_id=data.request_id)

    @admin.delete('/best-exits/{group_id}')
    def delete_best_exit(group_id: str, request_id: Identifier):
        return store_provider().delete_best_exit_group(group_id, request_id)

    @admin.get('/{agent_id}/traffic')
    def get_agent_traffic(agent_id: str):
        return store_provider().get_agent_traffic(agent_id)

    @agent.post('/traffic')
    def upload_agent_traffic(data: TrafficUploadRequest, authorization: str = Header(default='')):
        if not authorization.startswith('Bearer ') or len(authorization) > 160:
            raise HTTPException(status_code=401, detail='Invalid Agent credentials')
        items = [item.model_dump() for item in data.items]
        return store_provider().record_agent_traffic(
            authorization[7:], data.instance_id, data.batch_id, data.sequence, items,
        )

    @agent.post('/best-exit')
    def report_agent_best_exit(data: AgentBestExitReport, authorization: str = Header(default='')):
        from proxyforge.control.control_store import UnauthorizedAgent
        if not authorization.startswith('Bearer ') or len(authorization) > 160:
            raise UnauthorizedAgent()
        store = store_provider()
        with store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            auth_agent = store._authenticate(db, authorization[7:])
            row = db.execute('SELECT instance_id FROM agents WHERE id=?', (auth_agent,)).fetchone()
            grp = db.execute('SELECT agent_id FROM best_exit_groups WHERE id=?', (data.group_id,)).fetchone()
            if not row or row['instance_id'] != data.instance_id:
                raise UnauthorizedAgent()
            if not grp or grp['agent_id'] != auth_agent:
                raise HTTPException(status_code=404, detail='Best Exit group not found')
        probes = {eid: sample.model_dump() for eid, sample in data.probes.items()}
        return store.evaluate_best_exit_group(data.group_id, probes)
