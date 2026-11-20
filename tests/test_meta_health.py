import importlib.util,pathlib,time
spec=importlib.util.spec_from_file_location('health',pathlib.Path(__file__).parents[1] / 'libexec/meta-vpn-probe.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
good={'ok':True,'exit_ip':'8.8.4.4','source':'primary'}
bad={'ok':False,'reason':'Both independent HTTPS checks failed'}
c=h.Controller('vpngate_us','8.8.4.4')
assert c.step(bad,10)['mode']=='vpngate_us' and c.failures==1
assert c.step(good,20)['mode']=='vpngate_us' and c.failures==0
assert c.step(bad,30)['mode']=='vpngate_us'
assert c.step(bad,40)['mode']=='original'
assert c.step(good,50)['mode']=='original'
assert c.step(bad,60)['mode']=='original'
assert c.step(good,70)['mode']=='original'
assert c.step(good,80)['mode']=='vpngate_us'
assert c.step(bad|{'hard_failure':True,'reason':'VPN interface missing'},90)['mode']=='original'
original_cmd=h.cmd;original_request=h.request;original_atomic=h.atomic
class Result:returncode=0;stdout='[{"addr_info":[{"family":"inet","local":"10.211.1.29"}]}]'
h.cmd=lambda *a,**k:Result();h.atomic=lambda *a,**k:None
sequence=iter([({'ok':False,'http_code':0},''),({'ok':True,'http_code':200},'8.8.4.4')]);h.request=lambda url:next(sequence)
sample,_=h.probe({'last_us_ip':'8.8.4.4','verified_at':time.time()})
assert sample['ok'] and sample['source']=='independent IP verification'
sequence=iter([({'ok':False},''),({'ok':True},'8.8.8.8')]);h.request=lambda url:next(sequence)
sample,_=h.probe({'last_us_ip':'8.8.4.4','verified_at':time.time()});assert not sample['ok']
h.cmd=original_cmd;h.request=original_request;h.atomic=original_atomic
print('PASS: single failure holds, consecutive failure fallback, two-success recovery, hard failure, independent verification')
