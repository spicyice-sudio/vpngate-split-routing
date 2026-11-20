import importlib.util
import json
import pathlib
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pool', pathlib.Path(__file__).parents[1] / 'libexec/meta_vpn_pool.py')
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


def save(path, value):
    path.write_text(json.dumps(value))


with tempfile.TemporaryDirectory(prefix='pool-rank-', dir=pathlib.Path(__file__).parent) as temp:
    root = pathlib.Path(temp)
    assert root.resolve().is_relative_to(pathlib.Path(__file__).parent.resolve())
    pool.POOL = root / 'pool.json'
    pool.MANIFEST = root / 'standbys.json'
    pool.STATUS = root / 'status.json'
    pool.PRIMARY = root / 'primary.ovpn'
    pool.PRIMARY.write_text('remote 8.8.8.8 1194\n')
    nodes = [dict(id=ip, ip=ip, config='config '+ip) for ip in ['8.8.8.8','1.1.1.1','9.9.9.9','208.67.222.222']]
    results = [dict(id=node['id'], exit_ip=node['ip'], eligible=True, score=score)
               for node,score in zip(nodes,[500,10,100,80])]
    manifest = {'slots':[dict(slot=slot,id=ip,ip=ip,exit_ip=ip,verified_at=0,score=score,path=str(root/('standby-'+str(slot)+'.ovpn')))
                         for slot,ip,score in [(1,'1.1.1.1',10),(2,'9.9.9.9',100)]]}
    status = {'active_slot':0,'links':[dict(slot=slot,mode='vpngate_us') for slot in [0,1,2]]}
    save(pool.MANIFEST,manifest)
    save(pool.STATUS,status)
    def atomic(path, data):
        assert path.resolve().is_relative_to(root.resolve())
        path.write_bytes(data)
    with patch.object(pool.subprocess,'run'):
        held=pool.refresh(nodes,results,lambda raw,ip,dev:raw,atomic)
        assert [item['ip'] for item in held]==['1.1.1.1','9.9.9.9']
        ranked=pool.refresh(nodes,results,lambda raw,ip,dev:raw,atomic,rerank=True)
        assert [item['ip'] for item in ranked]==['208.67.222.222','9.9.9.9']
        save(pool.MANIFEST,manifest)
        narrow=[dict(item,score=score) for item,score in zip(results,[500,79,100,80])]
        upgraded=pool.refresh(nodes,narrow,lambda raw,ip,dev:raw,atomic,rerank=True)
        assert [item['ip'] for item in upgraded]==['208.67.222.222','9.9.9.9']
        save(pool.MANIFEST,manifest)
        ties=[dict(item,score=score) for item,score in zip(results,[500,80,100,80])]
        unchanged=pool.refresh(nodes,ties,lambda raw,ip,dev:raw,atomic,rerank=True)
        assert [item['ip'] for item in unchanged]==['1.1.1.1','9.9.9.9']
        save(pool.MANIFEST,manifest)
        save(pool.STATUS,status|{'active_slot':1})
        protected=pool.refresh(nodes,results,lambda raw,ip,dev:raw,atomic,rerank=True)
        assert [item['ip'] for item in protected]==['1.1.1.1','9.9.9.9']
print('PASS: repair preserves healthy tunnels, ranked pool upgrades slow backup, carrying backup remains protected')
