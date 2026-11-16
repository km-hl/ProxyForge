"""Pure standard-library unit tests for Phase 2 traffic accounting and nftables parser."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest

from agent.traffic_collector import (
    ReliableTrafficSpool,
    TrafficCounterState,
    collect_loopback_metrics,
    flush_gost_traffic,
    parse_gost_prometheus_metrics,
    parse_nftables_counters,
    render_nftables_forward_rules,
)

SAMPLE_METRICS = """# HELP gost_service_transfer_input_bytes_total Total input bytes
# TYPE gost_service_transfer_input_bytes_total counter
gost_service_transfer_input_bytes_total{host="node1",service="fwd_r1_tcp"} 1000
gost_service_transfer_input_bytes_total{host="node1",service="fwd_r1_udp"} 250
gost_service_transfer_output_bytes_total{host="node1",service="fwd_r1_tcp"} 2048
gost_service_transfer_output_bytes_total{host="node1",service="fwd_r1_udp"} 5.12e+02
gost_service_transfer_input_bytes_total{host="node1",service="relay_m1"} 900
gost_service_transfer_output_bytes_total{host="node1",service="relay_m1"} 1800
"""

SAMPLE_NFT = {
    'nftables': [
        {'metainfo': {'version': '1.0.9'}},
        {'rule': {
            'family': 'inet',
            'table': 'proxyforge',
            'chain': 'input_counters',
            'comment': 'proxyforge:forward:r1:in:tcp',
            'expr': [{'counter': {'packets': 10, 'bytes': 4096}}],
        }},
        {'rule': {
            'family': 'inet',
            'table': 'proxyforge',
            'chain': 'output_counters',
            'comment': 'proxyforge:forward:r1:out:tcp',
            'expr': [{'counter': {'packets': 12, 'bytes': 8192}}],
        }},
        {'rule': {
            'family': 'inet',
            'table': 'proxyforge',
            'chain': 'output_counters',
            'comment': 'unrelated-user-rule',
            'expr': [{'counter': {'packets': 99, 'bytes': 99999}}],
        }},
    ]
}


class TrafficCollectorTest(unittest.TestCase):
    def test_parse_prometheus_and_nftables_counters(self):
        parsed = parse_gost_prometheus_metrics(SAMPLE_METRICS)
        self.assertEqual(parsed['forward:r1'], {
            'resource_key': 'forward:r1',
            'forward_rule_id': 'r1',
            'rx_bytes': 1250,
            'tx_bytes': 2560,
        })
        self.assertEqual(parsed['relay:m1'], {
            'resource_key': 'relay:m1',
            'forward_rule_id': '',
            'rx_bytes': 900,
            'tx_bytes': 1800,
        })

        nft_parsed = parse_nftables_counters(SAMPLE_NFT)
        self.assertEqual(set(nft_parsed), {'forward:r1'})
        self.assertEqual(nft_parsed['forward:r1'], {
            'resource_key': 'forward:r1',
            'forward_rule_id': 'r1',
            'rx_bytes': 4096,
            'tx_bytes': 8192,
        })

        rules = render_nftables_forward_rules([
            {'id': 'r1', 'listen_port': 10000, 'protocol': 'tcp+udp', 'enabled': True},
            {'id': 'r2', 'listen_port': 10001, 'protocol': 'tcp', 'enabled': False},
        ])
        self.assertIn('tcp dport 10000 counter comment "proxyforge:forward:r1:in:tcp"', rules)
        self.assertIn('udp sport 10000 counter comment "proxyforge:forward:r1:out:udp"', rules)
        self.assertNotIn('r2', rules)

    def test_monotonic_delta_resilient_to_restart_and_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = TrafficCounterState(Path(tmp) / 'traffic-state.json')
            first = state.compute_deltas({
                'forward:r1': {'forward_rule_id': 'r1', 'rx_bytes': 1000, 'tx_bytes': 2000},
            }, epoch='ep1')
            self.assertEqual(len(first), 1)
            self.assertEqual(first[0]['items'][0]['rx_delta'], 1000)
            self.assertEqual(first[0]['items'][0]['tx_delta'], 2000)

            second = state.compute_deltas({
                'forward:r1': {'forward_rule_id': 'r1', 'rx_bytes': 1500, 'tx_bytes': 2600},
            }, epoch='ep1')
            self.assertEqual(second[0]['items'][0]['rx_delta'], 500)
            self.assertEqual(second[0]['items'][0]['tx_delta'], 600)

            # Daemon restarted and counter reset to small value < previous raw
            reset = state.compute_deltas({
                'forward:r1': {'forward_rule_id': 'r1', 'rx_bytes': 300, 'tx_bytes': 400},
            }, epoch='ep1')
            self.assertEqual(reset[0]['items'][0]['rx_delta'], 300)
            self.assertEqual(reset[0]['items'][0]['tx_delta'], 400)

            # New epoch resets baseline cleanly even if raw happened to exceed previous raw
            new_ep = state.compute_deltas({
                'forward:r1': {'forward_rule_id': 'r1', 'rx_bytes': 700, 'tx_bytes': 900},
            }, epoch='ep2')
            self.assertEqual(new_ep[0]['items'][0]['rx_delta'], 700)
            self.assertEqual(new_ep[0]['items'][0]['tx_delta'], 900)

            # Spool retries pending batch when upload fails cleanly
            spool = ReliableTrafficSpool(Path(tmp) / 'spool.json')
            pending = spool.compute_deltas({'forward:r2': {'forward_rule_id': 'r2', 'rx_bytes': 100, 'tx_bytes': 50}})
            self.assertEqual(len(pending), 1)
            pending2 = ReliableTrafficSpool(Path(tmp) / 'spool.json').compute_deltas(
                {'forward:r2': {'forward_rule_id': 'r2', 'rx_bytes': 100, 'tx_bytes': 50}}
            )
            self.assertEqual(len(pending2), 1)
            self.assertEqual(pending2[0]['batch_id'], pending[0]['batch_id'])
            spool.ack(pending[0]['batch_id'])
            self.assertEqual(ReliableTrafficSpool(Path(tmp) / 'spool.json').pending, [])

    def test_loopback_only_metrics_scrape_and_flush(self):
        for forbidden in ('198.51.100.1:18000', '0.0.0.0:18000', 'example.com:18000'):
            with self.assertRaises(ValueError):
                collect_loopback_metrics(forbidden)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = SAMPLE_METRICS.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                meta_path = root / 'metrics.json'
                meta_path.write_text(json.dumps({'metrics_addr': f'127.0.0.1:{port}', 'epoch': 'run1'}), encoding='utf-8')
                cfg_path = root / 'agent-config.json'
                uploaded = []

                class FakeClient:
                    def post(self, path, payload, token):
                        uploaded.append((path, payload, token))
                        return {'status': 'ok'}

                cfg = {'instance_id': 'a' * 32, 'token': 'pfagt_test'}
                count = flush_gost_traffic(FakeClient(), cfg, cfg_path, metrics_meta_path=meta_path)
                self.assertEqual(count, 2)
                self.assertEqual(uploaded[0][0], '/api/agent/traffic')
                # Next scrape with unchanged counters emits zero uploads
                self.assertEqual(flush_gost_traffic(FakeClient(), cfg, cfg_path, metrics_meta_path=meta_path), 0)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
