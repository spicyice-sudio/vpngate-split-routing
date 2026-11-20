import importlib.util
import json
import pathlib

spec = importlib.util.spec_from_file_location('failover', pathlib.Path(__file__).parents[1] / 'libexec/meta-vpn-health.py')
failover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(failover)
Selection, apply_routes = failover.Selection, failover.apply_routes


def link(slot, healthy=True, probe_ok=True):
    return {'slot': slot, 'mode': 'vpngate_us' if healthy else 'original',
            'probe_ok': probe_ok, 'device': 'vgmeta' + str(slot), 'local_ip': '10.211.1.1'}


s = Selection(0, 0)
assert s.choose([link(0), link(1), link(2)], 10) == 0
assert s.choose([link(0, False), link(1), link(2)], 20) == 1
assert s.choose([link(0), link(1), link(2)], 30) == 1
assert s.choose([link(0), link(1), link(2)], 400) == 1
assert s.choose([link(0), link(1), link(2)], 621) == 0
assert s.choose([link(0, False), link(1, False), link(2)], 630) == 2
assert s.choose([link(0, False), link(1, False), link(2, False)], 640) is None
assert s.choose([link(0, False), link(1), link(2, False)], 650) == 1
assert s.choose([link(0), link(1)], 660) == 1
assert s.choose([link(0, True, False), link(1)], 1200) == 1
assert s.choose([link(0), link(1)], 1210) == 1
assert s.choose([link(0), link(1)], 1511) == 0


class Network:
    TABLE = '51888'
    calls = []

    def cmd(self, args, check=False):
        self.calls.append(args)
        return type('Result', (), {'returncode': 0, 'stdout': json.dumps([{'metric': 0}, {'metric': 10}, {'metric': 102}])})()


network = Network()
apply_routes(network, [link(0, False), link(1), link(2)], 1)
assert network.calls[0][0:3] == ['ip', 'route', 'replace']
assert 'vgmeta1' in network.calls[0] and network.calls[0][-1] == '10'
assert 'vgmeta2' in network.calls[1] and network.calls[1][-1] == '102'
assert not any('flush' in args for args in network.calls)
class Disappeared(Network):
    def cmd(self, args, check=False):
        result = super().cmd(args, check)
        if 'replace' in args and 'vgmeta0' in args:
            result.returncode = 2
        return result
changing = [link(0), link(1), link(2)]
assert apply_routes(Disappeared(), changing, 0)
assert changing[0]['mode'] == 'original'
assert Selection(0, 0).choose(changing, 0) == 1
print('PASS: healthy standby selection, stable failback, and route replacement')
