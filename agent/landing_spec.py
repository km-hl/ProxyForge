"""Single-user SS2022 landing. No client subscription projection."""
import base64
import binascii

from .deployment_spec import validate_endpoint

LANDING_ACTIONS = ('landing.apply', 'landing.remove')
METHOD = '2022-blake3-aes-256-gcm'


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) != {'name', 'server', 'listen_port', 'method'}:
        raise ValueError('Invalid landing settings')
    validate_endpoint(settings)
    if settings['method'] != METHOD:
        raise ValueError('Unsupported landing method')


def validate_spec(action, spec):
    if action == 'landing.remove':
        if spec != {}:
            raise ValueError('Removal takes no configuration')
        return
    if action != 'landing.apply' or not isinstance(spec, dict) or set(spec) != {
            'name', 'server', 'listen_port', 'method', 'password'}:
        raise ValueError('Invalid landing specification')
    validate_settings({key: spec[key] for key in ('name', 'server', 'listen_port', 'method')})
    password = spec['password']
    try:
        if not isinstance(password, str) or len(password) != 44:
            raise ValueError('Invalid SS2022 key')
        decoded = base64.b64decode(password, validate=True)
        if len(decoded) != 32 or base64.b64encode(decoded).decode() != password:
            raise ValueError('Invalid SS2022 key')
    except (binascii.Error, ValueError):
        raise ValueError('Invalid SS2022 key') from None


def runtime_config(spec):
    validate_spec('landing.apply', spec)
    return {'log': {'level': 'warn'}, 'inbounds': [{
        'type': 'shadowsocks', 'tag': 'managed-landing', 'listen': '::',
        'listen_port': spec['listen_port'], 'method': METHOD, 'password': spec['password']
    }], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
