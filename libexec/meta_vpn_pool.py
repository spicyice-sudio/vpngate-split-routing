"""Maintain two persistent, separately verified US VPN standby profiles."""
import hashlib
import json
import pathlib
import subprocess
import time

DATA = pathlib.Path('/var/lib/meta-vpngate')
MANIFEST = DATA / 'standbys.json'
POOL = DATA / 'qualified-pool.json'
PRIMARY = pathlib.Path('/etc/meta-vpngate/client.ovpn')
STATUS = pathlib.Path('/run/meta-vpngate/status.json')
MAX_QUALIFIED = 12


def load(path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def refresh(nodes, results, sanitize, atomic, rerank=False):
    now = int(time.time())
    known = {item['id']: item for item in load(POOL, []) if now - item.get('verified_at', 0) < 86400}
    source = {node['id']: node for node in nodes}
    for result in results:
        key = result['id']
        if result.get('eligible') and key in source:
            known[key] = source[key] | {
                'verified_at': now, 'score': result['score'], 'exit_ip': result['exit_ip'],
            }
        else:
            known.pop(key, None)
    primary = PRIMARY.read_text()
    primary_ip = next(line.split()[1] for line in primary.splitlines() if line.startswith('remote '))
    status = load(STATUS, {})
    old = {item['slot']: item for item in load(MANIFEST, {'slots': []}).get('slots', [])}
    live = {link['slot']: link for link in status.get('links', [])}
    for slot, link in live.items():
        if slot in old and link.get('failure_streak', 0) >= 6:
            known.pop(old[slot]['id'], None)
    protected={item['id'] for slot,item in old.items() if live.get(slot,{}).get('mode')=='vpngate_us'}
    protected.update(item['id'] for item in known.values() if item['ip']==primary_ip)
    retained=sorted(known.values(),key=lambda item:(item['id'] not in protected,-item.get('score',0)))[:MAX_QUALIFIED]
    known={item['id']:item for item in retained}
    atomic(POOL, json.dumps(list(known.values())).encode())
    choices = sorted(known.values(), key=lambda item: -item.get('score', 0))
    used = {primary_ip}
    slots = []
    top_ids=[]
    top_ips={primary_ip}
    for item in choices:
        if item['ip'] not in top_ips:
            top_ips.add(item['ip'])
            top_ids.append(item['id'])
        if len(top_ids)==2:break
    # Keep the traffic-carrying backup and healthy incumbents still in the top two.
    reserved = {}
    for slot, item in sorted(old.items(), key=lambda pair: pair[0] != status.get('active_slot')):
        link = live.get(slot, {})
        keep=not rerank or slot==status.get('active_slot') or item['id'] in top_ids
        if link.get('mode') == 'vpngate_us' and item['ip'] not in used and keep:
            latest=known.get(item['id'],item)
            reserved[slot] = item | {key:latest[key] for key in ('verified_at','score')}
            used.add(item['ip'])
    for slot in (1, 2):
        if slot in reserved:
            slots.append(reserved[slot])
            continue
        candidate = next((item for item in choices if item['ip'] not in used), None)
        incumbent=old.get(slot)
        if rerank and incumbent and live.get(slot,{}).get('mode')=='vpngate_us' and incumbent['id'] in known and incumbent['ip'] not in used:
            measured=known[incumbent['id']]
            if candidate is None or candidate.get('score',0)<=measured.get('score',0):
                candidate=measured
        if candidate is None:
            # Leave a previously provisioned tunnel retrying if no fresh replacement exists.
            if slot in old and old[slot]['ip'] not in used:
                slots.append(old[slot])
                used.add(old[slot]['ip'])
            continue
        used.add(candidate['ip'])
        config = sanitize(candidate['config'], candidate['ip'], 'vgmeta' + str(slot)).encode()
        path = PRIMARY.parent / ('standby-' + str(slot) + '.ovpn')
        changed = not path.exists() or path.read_bytes() != config
        if changed:
            atomic(path, config)
        item = {key: candidate[key] for key in ('id', 'ip', 'exit_ip', 'verified_at', 'score')}
        item.update(slot=slot, path=str(path), sha256=hashlib.sha256(config).hexdigest())
        slots.append(item)
        if changed:
            subprocess.run(['systemctl', 'restart', 'meta-vpngate-backup@' + str(slot)], check=True, timeout=20)
    manifest = {'updated_at': now, 'slots': sorted(slots, key=lambda item: item['slot'])}
    atomic(MANIFEST, json.dumps(manifest).encode())
    return [{key: item[key] for key in ('slot', 'ip', 'verified_at')} for item in slots]


if __name__ == '__main__':
    import fcntl
    import importlib.util

    with open(DATA / 'scan.lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(0)
        spec = importlib.util.spec_from_file_location('selector', pathlib.Path(__file__).with_name('meta-vpngate-scan.py'))
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        print(json.dumps(refresh([], [], scanner.sanitize, scanner.atomic)), flush=True)
