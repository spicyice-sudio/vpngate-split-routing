import base64, importlib.util, json, pathlib, tempfile, time
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('scanner', pathlib.Path(__file__).parents[1] / 'libexec/meta-vpngate-scan.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
nodes = [{'id':str(i), 'ip':'8.8.8.8', 'advertised_score':100-i} for i in range(16)]
history = {}
first = m.select_batch(nodes, '0', history)
assert first[0]['id'] == '0' and len(first) == 6
for n in first: history[n['id']] = {'tested_at':100}
second = m.select_batch(nodes, '0', history)
assert second[0]['id'] == '0'
assert not ({n['id'] for n in first[1:]} & {n['id'] for n in second[1:]})
required=[dict(node,roles=['qualified']) for node in nodes[1:9]]
required[0]['roles'].append('standby1')
batch=m.select_batch([nodes[0]]+required+nodes[9:],'0',history)
assert {node['id'] for node in required}.issubset({node['id'] for node in batch})
assert len(batch)==12

def raw(ip): return 'client\nproto udp\nremote '+ip+' 1194\n<ca>\nTEST\n</ca>\n'
with tempfile.TemporaryDirectory(prefix='catalog-test-', dir=pathlib.Path(__file__).parent) as tmp:
    root = pathlib.Path(tmp)
    assert root.resolve().is_relative_to(pathlib.Path(__file__).parent.resolve())
    m.DATA = root; m.ACTIVE = root/'active.ovpn'; m.ACTIVE.write_text(raw('8.8.8.8'))
    m.STATUS=root/'status.json'
    now = int(time.time())
    cache = [{'id':'old', 'ip':ip, 'config':raw(ip), 'seen_at':now-age} for ip,age in [('9.9.9.9',48*3600),('1.0.0.1',96*3600)]]
    (root/'candidates.json').write_text(json.dumps(cache))
    csv = '#HostName,IP,Score,CountryShort,OpenVPN_ConfigData_Base64\nfresh,1.1.1.1,99,US,'+base64.b64encode(raw('1.1.1.1').encode()).decode()+'\n*\n'
    with patch.object(m.os, 'fchmod', lambda *args: None, create=True), patch.object(m, 'fetch', return_value=csv.encode()) as fetch:
        batch, errors, current, current_id = m.catalog()
    assert fetch.call_count == 1 and not errors
    assert {n['ip'] for n in batch} == {'8.8.8.8','9.9.9.9','1.1.1.1'}
    assert batch[0]['id'] == current_id
    assert json.loads((root/'catalog-report.json').read_text())['unique_ips'] == 3
    pool=[{'ip':'208.67.222.222','config':raw('208.67.222.222'),'verified_at':now}]
    (root/'qualified-pool.json').write_text(json.dumps(pool))
    (root/'standby-1.ovpn').write_text(raw('1.0.0.1'))
    (root/'standbys.json').write_text(json.dumps({'slots':[{'slot':1}]}))
    m.STATUS.write_text(json.dumps({'checked_at':now,'links':[{'slot':1,'mode':'vpngate_us','probe_ok':True}]}))
    with patch.object(m.os,'fchmod',lambda *args:None,create=True),patch.object(m,'fetch',return_value=csv.encode()):
        batch,errors,_,_=m.catalog()
    assert any(node['ip']=='208.67.222.222' and 'qualified' in node['roles'] for node in batch)
    assert any(node['ip']=='1.0.0.1' and node['live_device']=='vgmeta1' for node in batch)
    assert all('live_device' not in node and 'roles' not in node for node in json.loads((root/'candidates.json').read_text()))
    with patch.object(m,'measure',return_value={'eligible':True,'score':77}) as measure,patch.object(m.subprocess,'Popen',side_effect=AssertionError('Live tunnel must be reused')):
        warm=m.benchmark(next(node for node in batch if node['ip']=='1.0.0.1'))
    assert warm['eligible'] and warm['test_method']=='live_tunnel'
    measure.assert_called_once_with('vgmeta1')
print('PASS: production retained, batch rotation, 72-hour accumulation, expired cache removed, API US discovery')
