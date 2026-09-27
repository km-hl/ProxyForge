"""One additional Reality entry routed exclusively through an SS2022 landing."""
from .deployment_spec import validate_endpoint, validate_spec as validate_entry, runtime_config as entry_config
from .landing_spec import validate_spec as validate_landing

CHAIN_ACTIONS = ('chain.apply', 'chain.remove')


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) != {'name', 'listen_port'}:
        raise ValueError('Invalid chain settings')
    validate_endpoint({**settings, 'server': 'entry.example.com'})


def validate_spec(action, spec):
    if action not in CHAIN_ACTIONS or not isinstance(spec, dict) or set(spec) != {'direct', 'chain'}:
        raise ValueError('Invalid chain specification')
    validate_entry('deployment.apply', spec['direct'])
    if action == 'chain.remove':
        if spec['chain'] is not None:
            raise ValueError('Removal must preserve only the direct entry')
        return
    chain = spec['chain']
    if not isinstance(chain, dict) or set(chain) != {'entry', 'landing'}:
        raise ValueError('Invalid chain endpoints')
    validate_entry('deployment.apply', chain['entry'])
    validate_landing('landing.apply', chain['landing'])
    direct, entry = spec['direct'], chain['entry']
    if (entry['listen_port'] == direct['listen_port'] or entry['uuid'] == direct['uuid'] or
            entry['server'] != direct['server'] or entry['server_name'] != direct['server_name']):
        raise ValueError('Chain requires a separate entry on the same server')


def runtime_config(spec):
    validate_spec('chain.remove' if spec.get('chain') is None else 'chain.apply', spec)
    config = entry_config(spec['direct'])
    if spec['chain'] is None:
        return config
    inbound = entry_config(spec['chain']['entry'])['inbounds'][0]
    inbound['tag'] = 'managed-chain'
    config['inbounds'].append(inbound)
    landing = spec['chain']['landing']
    config['outbounds'].append({'type': 'shadowsocks', 'tag': 'landing', 'server': landing['server'],
                                'server_port': landing['listen_port'], 'method': landing['method'],
                                'password': landing['password'], 'domain_resolver': 'system'})
    config['dns'] = {'servers': [{'type': 'local', 'tag': 'system', 'prefer_go': True}]}
    config['route'] = {'rules': [{'inbound': ['managed-chain'], 'action': 'route', 'outbound': 'landing'}],
                       'final': 'direct'}
    return config
