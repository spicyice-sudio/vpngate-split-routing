#!/usr/bin/python3
"""Benchmark US VPN Gate nodes in a separate tunnel; never edit subscriptions."""
import argparse,base64,collections,csv,hashlib,html,ipaddress,json,math,os,pathlib,re,shlex,signal,statistics,subprocess,tempfile,time,urllib.parse,urllib.request

DATA=pathlib.Path('/var/lib/meta-vpngate')
ACTIVE=pathlib.Path('/etc/meta-vpngate/client.ovpn')
STATUS=pathlib.Path('/run/meta-vpngate/status.json')
DEV='vgscan0';TABLE='51900';PREF='12100'
MAX_NODES=6;MIN_IMPROVEMENT=1.25;MIN_HOLD_SECONDS=6*3600
CATALOG_TTL=72*3600;MAX_CACHED=100
SESSION=None
DIRECT_IPV4 = os.environ.get('VPN_GATE_DIRECT_IPV4') or None
INLINE_TLS = ('ca', 'cert', 'key', 'tls-auth', 'tls-crypt')

def command(args,check=False,timeout=20):
    return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=check)

def atomic(path,data,mode=0o600):
    path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as handle:handle.write(data);handle.flush();os.fsync(handle.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def save(path,value):atomic(path,json.dumps(value,indent=2).encode())

def fetch(url):
    parts=urllib.parse.urlsplit(url)
    if parts.scheme!='https' or parts.hostname!='www.vpngate.net':raise ValueError('Unexpected catalog URL')
    req=urllib.request.Request(url,headers={'User-Agent':'Meta-VPNGate-Selector/1.0'})
    with urllib.request.urlopen(req,timeout=25) as response:
        if urllib.parse.urlsplit(response.url).hostname!='www.vpngate.net':raise ValueError('Unexpected redirect')
        result=response.read(8*1024*1024+1)
        if len(result)>8*1024*1024:raise ValueError('Catalog too large')
        return result

def sanitize(raw,ip,dev):
    address = ipaddress.IPv4Address(ip)
    if len(raw) > 262144 or not address.is_global or address.is_multicast:
        raise ValueError('Invalid public VPN endpoint')
    if not re.fullmatch(r'[a-zA-Z0-9]+',dev):raise ValueError('Invalid tunnel name')
    options = {}
    remote = None
    blocks = {}
    active_tag = None
    content = []
    # Only whitelisted scalar options and inline TLS material are accepted.
    # Downloaded scripts, plugins, filenames, routes, proxies and hooks are ignored.
    for line in raw.splitlines():
        line = line.strip()
        if active_tag:
            if line == f'</{active_tag}>':
                if active_tag in INLINE_TLS:
                    if active_tag in blocks or not any(content):
                        raise ValueError('Duplicate or empty inline TLS block')
                    blocks[active_tag] = [f'<{active_tag}>', *content, line]
                active_tag = None
                content = []
            elif line.startswith('<'):
                raise ValueError('Malformed inline block')
            elif active_tag in INLINE_TLS:
                if '<' in line or '>' in line or '\x00' in line:
                    raise ValueError('Malformed TLS material')
                content.append(line)
            continue
        if not line or line.startswith(('#',';')):
            continue
        if line.startswith('<'):
            match = re.fullmatch(r'<([a-z0-9-]+)>', line)
            if not match:
                raise ValueError('Malformed inline block')
            active_tag = match[1]
            continue
        fields=shlex.split(line,comments=True)
        if not fields:continue
        key=fields[0]
        if key=='remote' and remote is None:
            if len(fields)<3 or not fields[2].isdigit() or not 1<=int(fields[2])<=65535:raise ValueError('Bad remote port')
            remote=int(fields[2])
        elif key in ['proto','cipher','auth','key-direction','comp-lzo']:
            if len(fields)!=2:raise ValueError('Bad scalar option')
            options[key]=fields[1]
    if active_tag or 'ca' not in blocks:
        raise ValueError('Missing or incomplete inline TLS block')
    if remote is None:raise ValueError('Missing VPN endpoint')
    proto=options.get('proto','udp')
    if proto not in ['udp','udp4','tcp','tcp-client','tcp4-client']:raise ValueError('Unsupported transport')
    proto='tcp-client' if proto.startswith('tcp') else 'udp'
    cipher=options.get('cipher','AES-128-CBC');auth=options.get('auth','SHA1')
    if cipher not in ['AES-128-CBC','AES-256-CBC','AES-128-GCM','AES-256-GCM','CHACHA20-POLY1305']:raise ValueError('Unsupported cipher')
    if auth not in ['SHA1','SHA256','SHA384','SHA512']:raise ValueError('Unsupported auth')
    lines=['client','dev '+dev,'dev-type tun','proto '+proto,'remote '+ip+' '+str(remote),'nobind','persist-key','persist-tun','route-nopull','route-noexec','remote-cert-tls server','auth-nocache','cipher '+cipher,'auth '+auth,'data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC','data-ciphers-fallback '+cipher,'connect-retry 10 30','connect-timeout 10','ping 10','ping-restart 20','verb 3','pull-filter ignore "redirect-gateway"','pull-filter ignore "dhcp-option"']
    if options.get('key-direction') in ['0','1']:lines.append('key-direction '+options['key-direction'])
    if 'comp-lzo' in options:
        if options['comp-lzo'] not in ['yes','no','adaptive']:raise ValueError('Unsupported compression')
        lines.extend(['comp-lzo '+options['comp-lzo'],'allow-compression asym'])
    for tag in INLINE_TLS:
        lines.extend(blocks.get(tag, []))
    return '\n'.join(lines)+'\n'

def endpoint(config):
    match=re.search(r'^remote\s+(\S+)\s+(\d+)',config,re.M)
    if not match:raise ValueError('Missing active endpoint')
    return match[1]

def select_batch(nodes,current_id,history):
    required=[node for node in nodes if node['id']==current_id or any(role!='discovery' for role in node.get('roles',[]))]
    required.sort(key=lambda node:(node['id']!=current_id,node['id']))
    required_ids={node['id'] for node in required}
    remaining=sorted((node for node in nodes if node['id'] not in required_ids),
        key=lambda node:(history.get(node['id'],{}).get('tested_at',0),-node.get('advertised_score',0),node['id']))
    return required+remaining[:max(3,MAX_NODES-len(required))]

def catalog():
    errors=[];nodes={};counts=collections.Counter();deadline=time.monotonic()+180
    def add(raw,ip,score=0,host='',source='api'):
        sanitized=sanitize(raw,ip,DEV);key=hashlib.sha256(sanitized.encode()).hexdigest()
        previous=nodes.get(key,{})
        # Hostname and IP versions of one endpoint are the same candidate.
        nodes[key]={'id':key,'ip':ip,'host':host or previous.get('host',''),'advertised_score':max(int(score or 0),previous.get('advertised_score',0)),'config':sanitized,'seen_at':int(time.time()),'sources':sorted(set(previous.get('sources',[])+[source])),'roles':previous.get('roles',[])}
        counts[source]+=1
    for url in ['https://www.vpngate.net/api/iphone/','https://www.vpngate.net/api/iphone/?t='+str(int(time.time()))]:
        try:
            lines=fetch(url).decode('utf-8-sig').splitlines();start=next(i for i,line in enumerate(lines) if line.startswith('#HostName,'))
            rows=csv.DictReader([lines[start].lstrip('#')]+[line for line in lines[start+1:] if line and not line.startswith('*')])
            for row in rows:
                if row.get('CountryShort')!='US' or not row.get('OpenVPN_ConfigData_Base64'):continue
                try:add(base64.b64decode(row['OpenVPN_ConfigData_Base64'],validate=True).decode('utf-8-sig'),row['IP'],row.get('Score'),row.get('HostName',''))
                except Exception as exc:errors.append('US entry rejected: '+str(exc))
            if nodes:break
        except Exception as exc:errors.append('API: '+str(exc))
    # Use HTML only if no US API nodes are available; accumulate API snapshots.
    if not nodes and time.monotonic()<deadline:
        try:
            page=fetch('https://www.vpngate.net/en/?t='+str(int(time.time()))).decode('utf-8-sig')
            web_nodes=0
            for row in re.findall(r'<tr\b[^>]*>.*?</tr>',page,re.S|re.I):
                if 'United States' not in row or 'do_openvpn.aspx' not in row:continue
                if time.monotonic()>=deadline or web_nodes>=10:break
                web_nodes+=1
                links=[html.unescape(link) for link in re.findall(r'href=[\"\x27]([^\"\x27]+)',row) if 'do_openvpn.aspx' in link]
                for link in links[:1]:
                    try:
                        params=urllib.parse.parse_qs(urllib.parse.urlsplit(link).query);ip=params['ip'][0]
                        configpage=fetch(urllib.parse.urljoin('https://www.vpngate.net/en/',link)).decode('utf-8-sig')
                        downloads=[html.unescape(x) for x in re.findall(r'href=[\"\x27]([^\"\x27]+)',configpage) if '.ovpn' in x]
                        for download in downloads[:2]:
                            if time.monotonic()>=deadline:break
                            try:add(fetch(urllib.parse.urljoin('https://www.vpngate.net/en/',download)).decode('utf-8-sig'),ip,host=params.get('fqdn',[''])[0],source='web')
                            except Exception as exc:errors.append('Web config: '+str(exc))
                    except Exception as exc:errors.append('Web node: '+str(exc))
        except Exception as exc:errors.append('Web list: '+str(exc))
    cache=DATA/'candidates.json'
    old=json.loads(cache.read_text()) if cache.exists() else []
    for item in old:
        if item.get('seen_at',0)>time.time()-CATALOG_TTL:
            try:
                normalized=sanitize(item['config'],item['ip'],DEV)
                key=hashlib.sha256(normalized.encode()).hexdigest()
                if key not in nodes:nodes[key]=item|{'id':key,'config':normalized}
            except Exception:pass
    current=ACTIVE.read_text();current_ip=endpoint(current);add(current,current_ip,source='active')
    current_id=hashlib.sha256(sanitize(current,current_ip,DEV).encode()).hexdigest()
    nodes[current_id]['roles']=['primary']
    pool_path=DATA/'qualified-pool.json'
    pool=json.loads(pool_path.read_text()) if pool_path.exists() else []
    manifest_path=DATA/'standbys.json'
    manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else {'slots':[]}
    def add_role(raw,ip,role):
        add(raw,ip,source=role)
        key=hashlib.sha256(sanitize(raw,ip,DEV).encode()).hexdigest()
        roles=nodes[key].setdefault('roles',[])
        if role not in roles:roles.append(role)
        return key
    for item in pool:
        if time.time()-item.get('verified_at',0)<86400:
            add_role(item['config'],item['ip'],'qualified')
    live_configs={0:ACTIVE}
    for item in manifest.get('slots',[]):
        slot=item['slot']
        path=ACTIVE.parent/('standby-'+str(slot)+'.ovpn')
        if slot in (1,2) and path.exists():
            raw=path.read_text()
            add_role(raw,endpoint(raw),'standby'+str(slot))
            live_configs[slot]=path
    status=json.loads(STATUS.read_text()) if STATUS.exists() else {}
    if time.time()-status.get('checked_at',0)<30:
        for link in status.get('links',[]):
            slot=link['slot']
            if slot in live_configs and link.get('mode')=='vpngate_us' and link.get('probe_ok'):
                raw=live_configs[slot].read_text()
                key=hashlib.sha256(sanitize(raw,endpoint(raw),DEV).encode()).hexdigest()
                if key in nodes:nodes[key]['live_device']='vgmeta'+str(slot)
    history_path=DATA/'probe-history.json'
    history=json.loads(history_path.read_text()) if history_path.exists() else {}
    old_report=DATA/'scan-report.json'
    if not history and old_report.exists():
        previous=json.loads(old_report.read_text())
        history={item['id']:{'tested_at':previous.get('finished_at',0)} for item in previous.get('results',[]) if item.get('id')}
    save(history_path,history)
    retained=sorted(nodes.values(),key=lambda n:(not n.get('roles'),n['id']!=current_id,-n.get('seen_at',0)))[:MAX_CACHED]
    listed=select_batch(retained,current_id,history)
    save(cache,[{key:value for key,value in node.items() if key not in ('roles','live_device')} for node in retained])
    save(DATA/'catalog-report.json',{'checked_at':int(time.time()),'source_entries':dict(counts),'unique_endpoints':len(retained),'unique_ips':len({n['ip'] for n in retained}),'batch_size':len(listed),'cache_hours':CATALOG_TTL//3600,'required_tested':sum(bool(n.get('roles')) for n in listed),'discovery_tested':sum(not n.get('roles') for n in listed)})
    return listed,errors,current_ip,hashlib.sha256(sanitize(current,current_ip,DEV).encode()).hexdigest()

def cleanup():
    global SESSION
    if SESSION is not None:
        if SESSION.poll() is None:
            SESSION.terminate()
            try:SESSION.wait(timeout=6)
            except subprocess.TimeoutExpired:SESSION.kill();SESSION.wait(timeout=3)
        SESSION=None
    command(['ip','route','flush','table',TABLE])
    command(['ip','rule','del','priority',PREF,'oif',DEV,'table',TABLE])

def abort(signum,frame):cleanup();raise SystemExit(128+signum)

def request(url,body=False,download=False,device=DEV):
    metrics='\n{"code":"%{http_code}","time":%{time_total},"ttfb":%{time_starttransfer},"bytes":%{size_download},"speed":%{speed_download}}'
    args=['curl','-4','--interface',device,'--noproxy','*','--silent','--show-error','--connect-timeout','3','--max-time','12' if download else '7']
    if not body:args+=['-o','/dev/null']
    if not body and not download:args+=['-I']
    result=command(args+['-w',metrics,url],timeout=15)
    try:content,tail=result.stdout.rsplit('\n',1);info=json.loads(tail)
    except Exception:return {'ok':False,'error':'No HTTPS result','time':15},''
    info['ok']=result.returncode==0 and 200<=int(info['code'])<400
    return info,content

def measure(device):
    trace,body=request('https://1.1.1.1/cdn-cgi/trace',body=True,device=device)
    fields=dict(line.split('=',1) for line in body.splitlines() if '=' in line)
    exit_ip = ipaddress.IPv4Address(fields.get('ip', ''))
    if not trace['ok'] or fields.get('loc')!='US' or not exit_ip.is_global or exit_ip.is_multicast or str(exit_ip)==DIRECT_IPV4:
        raise RuntimeError('US exit verification failed')
    probes={'trace':trace}
    for name,url in [('instagram','https://www.instagram.com/'),('threads','https://www.threads.com/'),('facebook','https://www.facebook.com/'),('whatsapp','https://www.whatsapp.com/'),('connectivity','https://www.gstatic.com/generate_204')]:
        probes[name]=request(url,device=device)[0]
    reliability=sum(bool(probe['ok']) for probe in probes.values())/len(probes)
    speed,_=request('https://speed.cloudflare.com/__down?bytes=524288',download=True,device=device)
    mbps=(speed.get('bytes',0)*8/max(speed.get('time',12),.001)/1000000) if speed['ok'] and speed.get('bytes')==524288 else 0
    latency=statistics.median(probe['ttfb'] for probe in probes.values() if probe.get('ok'))
    eligible=reliability>=.8 and all(probes[name]['ok'] for name in ['instagram','threads','facebook','whatsapp'])
    score=100*reliability**3*(.6/(latency+.15)+.4*math.log2(1+min(mbps,100))) if eligible else 0
    return dict(exit_ip=fields['ip'],country='US',eligible=eligible,reliability=reliability,
                median_ttfb_s=round(latency,3),download_mbps=round(mbps,3),score=round(score,3),https=probes)


def benchmark(node):
    global SESSION
    result={key:node.get(key) for key in ['id','ip','host','roles']};result['eligible']=False
    if node.get('live_device'):
        result['test_method']='live_tunnel'
        try:result.update(measure(node['live_device']))
        except Exception as exc:result['error']=str(exc)
        print(json.dumps({'benchmark':result}),flush=True)
        return result
    result['test_method']='isolated_tunnel'
    with tempfile.TemporaryDirectory(prefix='probe-',dir=DATA) as tmp:
        path=pathlib.Path(tmp);config=path/'client.ovpn';atomic(config,node['config'].encode())
        with open(path/'openvpn.log','wb') as log:
            try:
                SESSION=subprocess.Popen(['/usr/sbin/openvpn','--config',str(config)],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
                deadline=time.monotonic()+25
                while time.monotonic()<deadline:
                    if SESSION.poll() is not None:raise RuntimeError('VPN handshake failed')
                    logtext=(path/'openvpn.log').read_text(errors='replace')
                    if 'Initialization Sequence Completed' in logtext:break
                    time.sleep(0.5)
                else:raise RuntimeError('VPN handshake timeout')
                addr=command(['ip','-j','-4','addr','show','dev',DEV],True)
                ip=next(info['local'] for link in json.loads(addr.stdout) for info in link.get('addr_info',[]) if info.get('family')=='inet')
                command(['sysctl','-q','-w','net.ipv4.conf.'+DEV+'.rp_filter=2'])
                command(['ip','rule','add','priority',PREF,'oif',DEV,'table',TABLE],True)
                command(['ip','route','replace','default','dev',DEV,'src',ip,'table',TABLE],True)
                result.update(measure(DEV))
            except Exception as exc:result['error']=str(exc)
            finally:cleanup()
    print(json.dumps({'benchmark':result}),flush=True)
    return result

def choose(results,current_id,selected_at,now):
    good=[item for item in results if item.get('eligible')]
    if not good:return None,'No healthy US candidate; original-exit fallback remains available'
    best=max(good,key=lambda item:item['score'])
    current=next((item for item in good if item['id']==current_id),None)
    if current:
        if best['id']==current_id:return current,'Current node is best among tested candidates'
        if now-selected_at<MIN_HOLD_SECONDS:return current,'Minimum six-hour hold time'
        if best['score']<current['score']*MIN_IMPROVEMENT:return current,'Candidate improvement below 25 percent'
    return best,'Current node failed or candidate is at least 25 percent better'

def promote(node,measured):
    before=ACTIVE.read_bytes();candidate=sanitize(node['config'],node['ip'],'vgmeta0').encode()
    atomic(DATA/'client-before-last-switch.ovpn',before)
    atomic(ACTIVE,candidate)
    started=int(time.time())
    try:
        command(['systemctl','restart','meta-vpngate'],True,timeout=30)
        deadline=time.monotonic()+40
        while time.monotonic()<deadline:
            time.sleep(2)
            try:status=json.loads(STATUS.read_text())
            except Exception:continue
            primary=next((link for link in status.get('links',[]) if link.get('slot')==0),status)
            if status.get('checked_at',0)>=started and primary.get('mode')=='vpngate_us' and primary.get('exit_ip')==measured['exit_ip'] and primary.get('probe_ok',True):
                save(DATA/'selected.json',{'ip':node['ip'],'exit_ip':measured['exit_ip'],'selected_at':int(time.time()),'score':measured['score']});return
        raise RuntimeError('New production tunnel did not pass health check')
    except BaseException:
        atomic(ACTIVE,before);command(['systemctl','restart','meta-vpngate'],timeout=30)
        raise

def main():
    import fcntl

    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true', help='Benchmark and report without restarting VPN services')
    mode.add_argument('--seed-profile', nargs=2, metavar=('FILE', 'IPV4'),
                      help='Install an initial VPN Gate OpenVPN profile using its public endpoint IPv4')
    args = parser.parse_args()
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    with open(DATA/'scan.lock','w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:print('Another scan is running');return
        if args.seed_profile:
            path, ip = args.seed_profile
            if ACTIVE.exists():
                parser.error(f'{ACTIVE} already exists')
            atomic(ACTIVE, sanitize(pathlib.Path(path).read_text(encoding='utf-8-sig'), ip, 'vgmeta0').encode())
            print(f'Installed initial profile at {ACTIVE}')
            return
        # Only this scanner owns this name, table and rule priority.
        if command(['ip','link','show',DEV]).returncode==0:raise RuntimeError('Scan device already in use')
        if command(['ip','route','show','table',TABLE]).stdout.strip():raise RuntimeError('Scan route table already in use')
        if any(item.get('priority')==int(PREF) for item in json.loads(command(['ip','-j','rule','show'],True).stdout)):raise RuntimeError('Scan rule priority already in use')
        for sig in [signal.SIGTERM,signal.SIGINT]:signal.signal(sig,abort)
        default_before=command(['ip','route','show','default'],True).stdout
        started=int(time.time());nodes,errors,current_ip,current_id=catalog()
        selected=json.loads((DATA/'selected.json').read_text()) if (DATA/'selected.json').exists() else {}
        results=[]
        try:
            for node in nodes:
                results.append(benchmark(node))
                history_path=DATA/'probe-history.json'
                history=json.loads(history_path.read_text()) if history_path.exists() else {}
                history[node['id']]={'tested_at':int(time.time()),'eligible':results[-1]['eligible']}
                history={key:value for key,value in history.items() if value.get('tested_at',0)>time.time()-7*86400}
                save(history_path,history)
            best,reason=choose(results,current_id,selected.get('selected_at',0),int(time.time()))
            report={'started_at':started,'finished_at':int(time.time()),'country':'US','candidates_tested':len(results),'results':results,'catalog_errors':errors[:20],'decision':reason,'current_ip':current_ip,'chosen_ip':best['ip'] if best else None,'switched':False,'dry_run':args.dry_run}
            report['catalog']=json.loads((DATA/'catalog-report.json').read_text())
            if best and best['id']!=current_id and not args.dry_run:
                try:promote(next(node for node in nodes if node['id']==best['id']),best);report['switched']=True
                except Exception as exc:report['switch_error']=str(exc);report['decision']='Promotion failed; restored previous VPN configuration'
            elif best and best['id']==current_id and not args.dry_run and not (DATA/'selected.json').exists():
                save(DATA/'selected.json',{'ip':current_ip,'exit_ip':best['exit_ip'],'selected_at':int(time.time()),'score':best['score']})
            if not args.dry_run:
                from meta_vpn_pool import refresh
                report['standbys']=refresh(nodes,results,sanitize,atomic,rerank=True)
            default_after=command(['ip','route','show','default'],True).stdout
            if default_before!=default_after:raise RuntimeError('Unexpected global default-route change')
            report['global_default_route_unchanged']=True;save(DATA/'scan-report.json',report)
            print(json.dumps({key:report[key] for key in ['candidates_tested','decision','current_ip','chosen_ip','switched','global_default_route_unchanged']}),flush=True)
        finally:cleanup()

if __name__=='__main__':main()
