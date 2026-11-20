#!/usr/bin/python3
"""Keep verified US VPN tunnels ready and choose a healthy exit before direct fallback."""
import concurrent.futures
import importlib.util
import json
import pathlib
import signal
import sys
import time

DATA = pathlib.Path('/var/lib/meta-vpngate')
MANIFEST = DATA / 'standbys.json'
STATUS = pathlib.Path('/run/meta-vpngate/status.json')
HOLD_SECONDS = 600
PRIMARY_STABLE_SECONDS = 300


def probe_module(slot):
    path = pathlib.Path(__file__).with_name('meta-vpn-probe.py')
    spec = importlib.util.spec_from_file_location('vpn_probe_' + str(slot), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.DEV = 'vgmeta' + str(slot)
    module.PROBE = '51889' if slot == 0 else str(51910 + slot)
    module.MEMORY = DATA / ('health-memory.json' if slot == 0 else 'health-memory-' + str(slot) + '.json')
    return module


class Selection:
    def __init__(self, active=None, since=0):
        self.active = active
        self.since = since
        self.healthy_since = {}

    def choose(self, links, now):
        ready = {link['slot']: link for link in links if link['mode'] == 'vpngate_us'}
        for link in links:
            slot = link['slot']
            if link.get('probe_ok'):
                self.healthy_since.setdefault(slot, now)
            else:
                self.healthy_since.pop(slot, None)
        previous = self.active
        if self.active not in ready:
            self.active = min(ready, default=None)
        elif self.active != 0 and 0 in ready:
            stable = now - self.healthy_since.get(0, now) >= PRIMARY_STABLE_SECONDS
            if stable and now - self.since >= HOLD_SECONDS:
                self.active = 0
        if self.active != previous:
            self.since = now
        return self.active


def endpoint(path):
    try:
        for line in pathlib.Path(path).read_text().splitlines():
            if line.startswith('remote '):
                return line.split()[1]
    except OSError:
        pass
    return None


def inspect_link(module, controller, memory, slot, config):
    try:
        sample, local_ip = module.probe(memory)
        result = controller.step(sample, time.time())
    except Exception as error:
        result = controller.step({'ok': False, 'hard_failure': True, 'reason': type(error).__name__}, time.time())
        local_ip = None
    return result | {'slot': slot, 'device': module.DEV, 'local_ip': local_ip, 'endpoint_ip': endpoint(config)}


def apply_routes(module, links, active):
    desired = {}
    failed = False
    for link in links:
        if link['mode'] != 'vpngate_us' or not link.get('local_ip'):
            continue
        metric = 10 if link['slot'] == active else 100 + link['slot']
        result = module.cmd(['ip', 'route', 'replace', 'table', module.TABLE, 'default',
                             'dev', link['device'], 'src', link['local_ip'], 'metric', str(metric)])
        if result.returncode:
            link.update(mode='original', probe_ok=False, local_ip=None, reason='Tunnel changed while installing route')
            failed = True
        else:
            desired[metric] = link
    current = module.cmd(['ip', '-j', 'route', 'show', 'table', module.TABLE])
    for route in json.loads(current.stdout or '[]'):
        metric = route.get('metric', 0)
        if metric not in desired:
            module.cmd(['ip', 'route', 'del', 'table', module.TABLE, 'default', 'metric', str(metric)])
    return failed


def main():
    modules = {slot: probe_module(slot) for slot in range(3)}
    base = modules[0]

    def clear(*args):
        base.clear()
        for slot in (1, 2):
            base.cmd(['ip', 'route', 'flush', 'table', modules[slot].PROBE])
        if args:
            raise SystemExit(0)

    if 'clear' in sys.argv:
        clear()
        return
    base.rules()
    existing = json.loads(base.cmd(['ip', '-j', 'rule', 'show'], True).stdout)
    for slot in (1, 2):
        priority = 11980 + slot
        found = [rule for rule in existing if rule.get('priority') == priority]
        if found:
            if str(found[0].get('table')) != modules[slot].PROBE or found[0].get('oif') != modules[slot].DEV:
                raise RuntimeError('Backup routing priority already occupied')
        else:
            base.cmd(['ip', 'rule', 'add', 'priority', str(priority), 'oif', modules[slot].DEV,
                      'table', modules[slot].PROBE], True)
    signal.signal(signal.SIGTERM, clear)
    signal.signal(signal.SIGINT, clear)
    old = base.read(STATUS, {})
    active = old.get('active_slot', 0 if old.get('mode') == 'vpngate_us' else None)
    selector = Selection(active, old.get('selected_since', time.time()))
    controllers = {slot: module.Controller() for slot, module in modules.items()}
    if active is not None and old.get('mode') == 'vpngate_us':
        controllers[active] = base.Controller('vpngate_us', old['exit_ip'])
    memories = {slot: module.read(module.MEMORY, {}) for slot, module in modules.items()}
    signatures = {}
    previous = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        while True:
            started = time.monotonic()
            manifest = base.read(MANIFEST, {'slots': []})
            configs = {0: '/etc/meta-vpngate/client.ovpn'}
            configs.update({item['slot']: item['path'] for item in manifest.get('slots', [])})
            try:
                futures = []
                for slot, config in sorted(configs.items()):
                    raw = pathlib.Path(config).read_bytes()
                    if slot in signatures and signatures[slot] != raw:
                        controllers[slot] = base.Controller()
                        memories[slot] = {}
                    signatures[slot] = raw
                    futures.append(executor.submit(inspect_link, modules[slot], controllers[slot], memories[slot], slot, config))
                links = [future.result() for future in futures]
                for attempt in range(len(links) + 1):
                    active = selector.choose(links, time.time())
                    if not apply_routes(base, links, active):
                        break
                chosen = next((link for link in links if link['slot'] == active), None)
                now = int(time.time())
                ready = [link for link in links if link['mode'] == 'vpngate_us']
                status = {
                    'mode': 'vpngate_us' if chosen else 'original',
                    'exit_ip': chosen['exit_ip'] if chosen else base.DIRECT_IPV4,
                    'checked_at': now,
                    'probe_ok': chosen.get('probe_ok', False) if chosen else False,
                    'degraded': chosen.get('degraded', False) if chosen else False,
                    'active_slot': active,
                    'selected_since': selector.since,
                    'route_role': ('primary' if active == 0 else 'backup') if chosen else 'original',
                    'reason': 'Healthy VPN selected before original exit' if chosen else 'All configured VPN tunnels failed health checks',
                    'ready_backups': sum(link['slot'] != active for link in ready),
                    'links': links,
                }
                if chosen:
                    status['country'] = 'US'
                    status['last_us_ip'] = chosen['exit_ip']
                base.atomic(STATUS, status)
                identity = (status['mode'], active, status['exit_ip'])
                if identity != previous:
                    print(json.dumps(status), flush=True)
                    previous = identity
            except Exception as error:
                # Keep the last installed routes while systemd restarts a failed manager.
                print('Failover manager error: ' + type(error).__name__, flush=True)
                raise
            time.sleep(max(.1, base.INTERVAL - (time.monotonic() - started)))


if __name__ == '__main__':
    main()
