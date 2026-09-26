"""Bounded VLESS Reality specification shared by Controller and root helper."""
import base64
import hashlib
import ipaddress
import json
import re
import uuid

DEPLOYMENT_ACTIONS = ('deployment.apply', 'deployment.remove')


def host(value, domain_only=False):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError('Invalid host')
    try:
        ipaddress.ip_address(value)
        if domain_only:
            raise ValueError('A DNS name is required')
        return
    except ValueError:
        pass
    if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', value):
        raise ValueError('Invalid DNS name')


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) != {'name', 'server', 'server_name', 'listen_port'}:
        raise ValueError('Invalid deployment settings')
    validate_endpoint(settings)
    host(settings['server_name'], domain_only=True)


def validate_endpoint(settings):
    name = settings['name']
    if not isinstance(name, str) or not name.strip() or len(name) > 64 or any(ord(c) < 32 for c in name):
        raise ValueError('Invalid name')
    host(settings['server'])
    if type(settings['listen_port']) is not int or not 1 <= settings['listen_port'] <= 65535:
        raise ValueError('Invalid port')


def spec_hash(spec):
    return hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_reference(payload):
    if (not isinstance(payload, dict) or set(payload) != {'deployment_id', 'revision', 'spec_hash'} or
            not isinstance(payload['deployment_id'], str) or not re.fullmatch('[a-f0-9]{32}', payload['deployment_id']) or
            type(payload['revision']) is not int or not 1 <= payload['revision'] <= 2147483647 or
            not isinstance(payload['spec_hash'], str) or not re.fullmatch('[a-f0-9]{64}', payload['spec_hash'])):
        raise ValueError('Invalid deployment reference')


def validate_spec(action, spec):
    if action == 'deployment.remove':
        if spec != {}:
            raise ValueError('Removal takes no configuration')
        return
    if action != 'deployment.apply' or not isinstance(spec, dict) or set(spec) != {
            'name', 'server', 'server_name', 'listen_port', 'uuid', 'private_key', 'public_key', 'short_id'}:
        raise ValueError('Invalid deployment specification')
    validate_settings({key: spec[key] for key in ('name', 'server', 'server_name', 'listen_port')})
    if not isinstance(spec['uuid'], str) or str(uuid.UUID(spec['uuid'])) != spec['uuid']:
        raise ValueError('Invalid UUID')
    for key in ('private_key', 'public_key'):
        value = spec[key]
        if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', value):
            raise ValueError('Invalid Reality key')
        if base64.urlsafe_b64encode(base64.urlsafe_b64decode(value + '=')).decode().rstrip('=') != value:
            raise ValueError('Invalid Reality key encoding')
    if not isinstance(spec['short_id'], str) or not re.fullmatch('[a-f0-9]{16}', spec['short_id']):
        raise ValueError('Invalid short ID')


def runtime_config(spec):
    validate_spec('deployment.apply', spec)
    return {'log': {'level': 'warn'}, 'inbounds': [{
        'type': 'vless', 'tag': 'managed-vless', 'listen': '::', 'listen_port': spec['listen_port'],
        'users': [{'uuid': spec['uuid'], 'flow': 'xtls-rprx-vision'}],
        'tls': {'enabled': True, 'server_name': spec['server_name'], 'reality': {
            'enabled': True, 'handshake': {'server': spec['server_name'], 'server_port': 443},
            'private_key': spec['private_key'], 'short_id': [spec['short_id']]}}
    }], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}


def node_name(identifier, name):
    return name + ' [pf:' + identifier + ']'


def client_node(identifier, agent_id, spec):
    return {'name': node_name(identifier, spec['name']), 'type': 'vless',
            'server': spec['server'], 'port': spec['listen_port'], 'uuid': spec['uuid'],
            'network': 'tcp', 'tls': True, 'udp': True, 'flow': 'xtls-rprx-vision',
            'servername': spec['server_name'], 'client-fingerprint': 'chrome',
            'reality-opts': {'public-key': spec['public_key'], 'short-id': spec['short_id']},
            '_managed_by': {'type': 'agent', 'agent_id': agent_id, 'deployment_id': identifier}}
