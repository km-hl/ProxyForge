"""Secret-free management inventory, including nodes withheld from subscriptions."""
import json

from agent.deployment_spec import node_name


class ManagedInventoryMixin:
    def managed_inventory(self):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            for row in db.execute("SELECT DISTINCT agent_id FROM jobs WHERE status IN ('pending','assigned','running')").fetchall():
                self._expire_jobs(db, row['agent_id'])
            agents = {}
            for row in db.execute('SELECT * FROM agents'):
                view = self._view(row)
                agents[row['id']] = {key: view[key] for key in ('id', 'name', 'status', 'last_seen', 'compatible')}
            jobs = {row['id']: dict(row) for row in db.execute('''SELECT id,type,status,error FROM jobs
                WHERE id IN (SELECT job_id FROM deployments UNION SELECT job_id FROM chains)''')}
            # Never load or decrypt secret_spec; this page also works during key recovery.
            deployments = {row['agent_id']: dict(row) for row in db.execute(
                'SELECT id,agent_id,protocol,settings,revision,job_id,updated_at FROM deployments')}
            chains = [dict(row) for row in db.execute(
                'SELECT id,agent_id,landing_agent_id,settings,revision,job_id,updated_at FROM chains')]
            items = []
            for record, kind in [(row, 'direct') for row in deployments.values() if row['protocol'] == 'vless-reality'] + [
                    (row, 'chain') for row in chains]:
                agent, job = agents[record['agent_id']], jobs[record['job_id']]
                settings = json.loads(record['settings'])
                landing = agents[record['landing_agent_id']] if kind == 'chain' else None
                removed = job['type'].endswith('.remove') and job['status'] == 'success'
                publishable = (job['status'] == 'success' and job['type'].endswith('.apply') and
                               agent['status'] != 'revoked' and (landing is None or landing['status'] != 'revoked'))
                blocked_by = []
                if kind == 'direct':
                    blocked_by = [{'id': row['id'], 'name': json.loads(row['settings'])['name']}
                                  for row in chains if row['agent_id'] == agent['id'] and not (
                                      jobs[row['job_id']]['type'] == 'chain.remove' and jobs[row['job_id']]['status'] == 'success')]
                source = deployments.get(record['agent_id'])
                endpoint = json.loads(source['settings'])['server'] if source else ''
                items.append({'id': record['id'], 'kind': kind, 'name': node_name(record['id'], settings['name']),
                              'agent': agent, 'landing': landing, 'server': endpoint, 'port': settings['listen_port'],
                              'revision': record['revision'], 'job_id': record['job_id'], 'action': job['type'],
                              'status': job['status'], 'error': job['error'], 'removed': removed,
                              'publishable': publishable, 'blocked_by': blocked_by, 'updated_at': record['updated_at']})
            return sorted(items, key=lambda item: (item['agent']['name'], item['agent']['id'], item['kind'] == 'chain', item['id']))
