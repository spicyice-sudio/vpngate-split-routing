#!/usr/bin/python3
"""VPN health with independent verification and fail/recovery hysteresis."""
import subprocess,json,pathlib,time,ipaddress,os,tempfile
DEV='vgmeta0';TABLE='51888';PROBE='51889';MARK='51888'
STATE=pathlib.Path('/run/meta-vpngate/status.json')
MEMORY=pathlib.Path('/var/lib/meta-vpngate/health-memory.json')
INTERVAL=10;FAILURES_TO_FALLBACK=2;SUCCESSES_TO_RECOVER=2
DIRECT_IPV4 = os.environ.get('VPN_GATE_DIRECT_IPV4') or None

def read(path,default=None):
    try:return json.loads(pathlib.Path(path).read_text())
    except (OSError,ValueError):return default

def atomic(path,value,mode=0o644):
    path=pathlib.Path(path);path.parent.mkdir(exist_ok=True,parents=True)
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'w') as stream:json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def cmd(args,check=False):return subprocess.run(args,capture_output=True,text=True,timeout=12,check=check)

def rules():
    found=json.loads(cmd(['ip','-j','rule','show'],True).stdout)
    for pref,args in [(12000,['fwmark',MARK,'table',TABLE]),(11990,['oif',DEV,'table',PROBE])]:
        existing=[item for item in found if item.get('priority')==pref]
        if not existing:cmd(['ip','rule','add','priority',str(pref)]+args,True)
        elif str(existing[0].get('table'))!=args[-1]:raise RuntimeError('Routing priority already used')

def clear():
    cmd(['ip','route','flush','table',TABLE]);cmd(['ip','route','flush','table',PROBE])
    if STATE.parent.exists():
        old=read(STATE,{})
        atomic(STATE,{'mode':'original','exit_ip':DIRECT_IPV4,'reason':'VPN stopped or health service unavailable','checked_at':int(time.time()),'last_us_ip':old.get('last_us_ip') or (old.get('exit_ip') if old.get('mode')=='vpngate_us' else None)})

class Controller:
    def __init__(self,mode='original',exit_ip=DIRECT_IPV4):
        self.mode=mode;self.exit_ip=exit_ip;self.failures=0;self.successes=0;self.last_success_ip=None
    def step(self,sample,now):
        if sample.get('ok'):
            ip=sample['exit_ip'];self.failures=0
            self.successes=self.successes+1 if self.last_success_ip==ip else 1;self.last_success_ip=ip
            if self.mode=='vpngate_us' or self.successes>=SUCCESSES_TO_RECOVER:
                self.mode='vpngate_us';self.exit_ip=ip;reason='VPN HTTPS health verified: '+sample.get('source','primary')
            else:reason='Waiting for second consecutive successful recovery check'
        else:
            self.failures+=1;self.successes=0;self.last_success_ip=None
            if sample.get('hard_failure') or self.failures>=FAILURES_TO_FALLBACK or self.mode=='original':
                self.mode='original';self.exit_ip=DIRECT_IPV4;reason=sample.get('reason','Consecutive HTTPS health checks failed')
            else:reason='Single failed health sample; preserving the VPN route'
        return {'mode':self.mode,'exit_ip':self.exit_ip,'reason':reason,'checked_at':int(now),'probe_ok':bool(sample.get('ok')),'failure_streak':self.failures,'recovery_successes':self.successes,'degraded':self.mode=='vpngate_us' and not sample.get('ok'),'probe':sample.get('details',{})}

def request(url):
    try:
        result=subprocess.run(['curl','-4','--interface',DEV,'--noproxy','*','--connect-timeout','2','--max-time','4','--silent','--show-error','-w','\n%{http_code} %{time_total}',url],capture_output=True,text=True,timeout=6)
        body,tail=result.stdout.rsplit('\n',1);status,elapsed=tail.split()
        return {'ok':result.returncode==0 and status=='200','http_code':int(status),'elapsed_s':float(elapsed),'curl_exit':result.returncode},body.strip()
    except Exception as exc:return {'ok':False,'error':type(exc).__name__},''

def public_ip(value):
    try:
        address = ipaddress.IPv4Address(value)
        return address.is_global and not address.is_multicast and str(address) != DIRECT_IPV4
    except ValueError:return False

def probe(memory):
    info=cmd(['ip','-j','-4','addr','show','dev',DEV])
    if info.returncode:return {'ok':False,'hard_failure':True,'reason':'VPN interface missing','details':{}},None
    v4=[entry['local'] for link in json.loads(info.stdout) for entry in link.get('addr_info',[]) if entry.get('family')=='inet']
    if not v4:return {'ok':False,'hard_failure':True,'reason':'VPN interface has no IPv4 address','details':{}},None
    cmd(['sysctl','-q','-w','net.ipv4.conf.'+DEV+'.rp_filter=2'])
    cmd(['ip','route','replace','default','dev',DEV,'src',v4[0],'table',PROBE],True)
    primary,body=request('https://1.1.1.1/cdn-cgi/trace');details={'primary':primary}
    fields=dict(line.split('=',1) for line in body.splitlines() if '=' in line)
    if primary['ok'] and public_ip(fields.get('ip','')):
        if fields.get('loc')!='US':return {'ok':False,'hard_failure':True,'reason':'VPN exit country verification failed','details':details},v4[0]
        memory.update(last_us_ip=fields['ip'],verified_at=int(time.time()))
        atomic(MEMORY,memory,0o600)
        return {'ok':True,'exit_ip':fields['ip'],'source':'primary','details':details},v4[0]
    secondary,body=request('https://api.ipify.org');details['secondary']=secondary
    if secondary['ok'] and public_ip(body) and body==memory.get('last_us_ip') and time.time()-memory.get('verified_at',0)<86400:
        return {'ok':True,'exit_ip':body,'source':'independent IP verification','details':details},v4[0]
    return {'ok':False,'reason':'Both independent HTTPS checks failed','details':details},v4[0]
