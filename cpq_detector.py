#!/usr/bin/env python3
import argparse, asyncio, csv, json, os, random, re, signal, sys, time
from urllib.parse import urljoin, urlparse
import aiohttp, tldextract
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

ua = UserAgent()

CHECKPOINT_FILE="cpq_checkpoint.json"; RESULTS_FILE="cpq_results.csv"; ERRORS_FILE="cpq_errors.csv"
MAX_HTML_BYTES=2500000; MAX_ASSET_BYTES=1500000; MAX_SCRIPTS=20; MAX_LINKS=15; SAVE_EVERY=100
STOP=False

FINGERPRINTS={
"Salesforce CPQ":{"strong":[r"\bSBQQ__",r"\bSBQQ\b",r"/apex/SBQQ",r"SBQQ\.Quote", r"window\.SBQQ"],"medium":[r"salesforce.*cpq",r"quote line editor", r"steelbrick"],"domains":["salesforce.com","force.com","visualforce.com", "steelbrick.com"]},
"ConnectWise CPQ":{"strong":[r"connectwise.*cpq",r"connectwise.*sell",r"quote\.connectwise",r"sell\.connectwise"],"medium":[r"connectwise sell"],"domains":["connectwise.com"]},
"Oracle CPQ":{"strong":[r"/cpq/rest/",r"/bmi/",r"oraclecpq",r"cpq\.oraclecloud",r"bigmachines",r"bm\.oracle", r"BIGipServer[a-zA-Z0-9_]*CPQ"],"medium":[r"oracle.*cpq"],"domains":["oraclecloud.com","bigmachines.com"]},
"Model N CPQ":{"strong":[r"modeln.*cpq",r"model n.*configure.*price"],"medium":[r"model n.*cpq"],"domains":["modeln.com"]},
"Conga CPQ":{"strong":[r"conga.*cpq",r"apttus.*cpq",r"\bApttus__",r"\bApttus\b"],"medium":[r"conga quote"],"domains":["conga.com","apttus.com"]},
"IBM Sterling CPQ":{"strong":[r"ibm.*sterling.*cpq",r"sterling.*configure.*price.*quote"],"medium":[r"ibm sterling.*cpq"],"domains":["ibm.com"]},
"Cincom CPQ":{"strong":[r"cincom.*cpq",r"cincom eloquence",r"cincom configure"],"medium":[r"cincom.*quote"],"domains":["cincom.com"]},
"Experlogix CPQ":{"strong":[r"experlogix.*cpq",r"experlogix.*configuration", r"cdn\.experlogix\.com"],"medium":[r"experlogix.*quote"],"domains":["experlogix.com"]},
"Tacton CPQ":{"strong":[r"tacton.*cpq",r"tacton configurator"],"medium":[r"tacton.*quote"],"domains":["tacton.com"]},
"SAP CPQ":{"strong":[r"sap.*cpq",r"calliduscloud.*cpq",r"calliduscloud"],"medium":[r"configure.*price.*quote.*sap"],"domains":["sap.com","calliduscloud.com"]},
"Zuora CPQ":{"strong":[r"zuora.*cpq",r"zuora quotes"],"medium":[r"zuora quote"],"domains":["zuora.com"]},
"Infor CPQ":{"strong":[r"infor.*cpq",r"infor configure price quote",r"infor configurator"],"medium":[r"infor.*quote"],"domains":["infor.com"]},
"FPX CPQ":{"strong":[r"\bfpx cpq\b",r"fpx.*configure.*price"],"medium":[r"\bfpx\b.*quote"],"domains":["fpx.com"]},
"Technicon CPQ":{"strong":[r"technicon.*cpq",r"technicon.*configur"],"medium":[r"technicon.*quote"],"domains":[]},
"Powertrak CPQ":{"strong":[r"powertrak.*cpq",r"powertrak.*configur"],"medium":[r"powertrak.*quote"],"domains":[]},
"ServiceNow CPQ":{"strong":[r"servicenow.*cpq",r"configure.*price.*quote.*servicenow"],"medium":[r"servicenow.*quote"],"domains":["servicenow.com"]},
"e-Con CPQ":{"strong":[r"e-con.*cpq",r"e-con solutions.*cpq",r"e-con.*configurator"],"medium":[],"domains":[]},
"Epicor CPQ":{"strong":[r"epicor.*cpq",r"epicor configurator",r"kbmax"],"medium":[r"epicor.*quote"],"domains":["epicor.com","kbmax.com"]},
"Zilliant CPQ":{"strong":[r"zilliant.*cpq"],"medium":[r"zilliant.*quote"],"domains":["zilliant.com"]},
"BigTime Services CPQ":{"strong":[r"bigtime.*cpq",r"bigtime services.*quote"],"medium":[],"domains":[]},
"Right Information CPQ Platform":{"strong":[r"right information.*cpq",r"rightinformation.*cpq"],"medium":[],"domains":[]},
"Sculptor CPQ":{"strong":[r"sculptor.*cpq",r"sculptor configurator"],"medium":[],"domains":[]},
"servicePath CPQ+":{"strong":[r"servicepath.*cpq",r"servicepath.*quote"],"medium":[],"domains":[]},
"Lino 3D Configuration & CPQ":{"strong":[r"lino.*cpq",r"lino 3d.*configur"],"medium":[r"lino.*configurator"],"domains":["lino.de"]},
"Mobileforce CPQ":{"strong":[r"mobileforce.*cpq",r"mobileforce.*quote"],"medium":[],"domains":["mobileforcesoftware.com"]},
"Solidify CPQ":{"strong":[r"solidify.*cpq",r"solidify.*quote"],"medium":[],"domains":[]},
"Veloce CPQ":{"strong":[r"veloce.*cpq",r"veloce configurator"],"medium":[],"domains":[]},
"Ventas CPQ & SMS Solution":{"strong":[r"ventas.*cpq",r"ventas.*sms.*solution"],"medium":[],"domains":[]},
"PROS CPQ":{"strong":[r"pros.*cpq",r"pros smart cpq"],"medium":[r"pros quote"],"domains":["pros.com"]},
"DealHub CPQ":{"strong":[r"dealhub.*cpq",r"dealhub\.io"],"medium":[r"dealhub quote"],"domains":["dealhub.io"]},
"Logik.io":{"strong":[r"logik\.io",r"logikio"],"medium":[],"domains":["logik.io"]},
"Vlocity CPQ":{"strong":[r"vlocity.*cpq",r"vlocity configurator"],"medium":[r"vlocity quote"],"domains":["vlocity.com"]},
"ThreeKit":{"strong":[r"threekit.*cpq",r"threekit 3d configurator"],"medium":[r"threekit"],"domains":["threekit.com"]},
"Expedite Commerce":{"strong":[r"expedite.*commerce",r"expeditecommerce"],"medium":[],"domains":[]}
}

def stop_handler(*_):
 global STOP; STOP=True; print("\\nStopping safely...")
signal.signal(signal.SIGINT,stop_handler)

def norm(v):
 if not v:return None
 v=str(v).strip().replace("\ufeff","")
 if "://" not in v:v="https://"+v
 h=urlparse(v).netloc.lower().split("@")[-1].split(":")[0].strip(".")
 return h if h and "." in h else None

def reg(h):
 e=tldextract.extract(h); return ".".join(x for x in (e.domain,e.suffix) if x) or h

def conf(s):
 return "CONFIRMED" if s>=90 else "LIKELY" if s>=60 else "POSSIBLE" if s>=15 else "NOT_DETECTED"

def snippet(t,a,b):
 return re.sub(r"\s+"," ",t[max(0,a-120):min(len(t),b+180)]).strip()

def detect(text,label):
 low=text.lower(); out=[]
 for vendor,fp in FINGERPRINTS.items():
  score=0; ev=[]
  for patterns,pts,name in ((fp["strong"],50,"STRONG"),(fp["medium"],20,"MEDIUM")):
   for p in patterns:
    try:m=re.search(p,low,re.I)
    except re.error:m=None
    if m: score+=pts; ev.append(f"[{label}] {name}: "+snippet(text,m.start(),m.end()))
  for d in fp["domains"]:
   if d.lower() in low: score+=35; ev.append(f"[{label}] VENDOR_DOMAIN: {d}")
  score=min(100,score)
  if score>=20:out.append((vendor,score,ev[:6]))
 return out

async def fetch(session,url,timeout,max_bytes, verify_ssl=True):
 headers = {
  'User-Agent': ua.random,
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
  'Accept-Encoding': 'gzip, deflate, br',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-User': '?1'
 }
 try:
  async with session.get(url,allow_redirects=True,timeout=aiohttp.ClientTimeout(total=timeout), headers=headers, ssl=verify_ssl) as r:
   chunks=[]; n=0
   async for c in r.content.iter_chunked(65536):
    chunks.append(c); n+=len(c)
    if n>=max_bytes:break
   raw=b"".join(chunks)
   try:body=raw.decode(r.charset or "utf-8",errors="ignore")
   except LookupError:body=raw.decode("utf-8",errors="ignore")
   headers_str="\\n".join(f"{k}: {v}" for k,v in r.headers.items())
   cookies="\\n".join(f"{k}: {v.value}" for k,v in r.cookies.items())
   return True,str(r.url),r.status,body,headers_str,cookies,""
 except Exception as e:return False,url,"","","","","%s: %s"%(type(e).__name__,str(e)[:250])

def scripts(base, soup):
 return [urljoin(base, x.get('src')) for x in soup.find_all('script') if x.get('src') and urljoin(base, x.get('src')).startswith(("http://","https://"))][:MAX_SCRIPTS]

def links(base, soup):
 kws=("configur","quote","pricing","price","build","custom","product","rfq","commerce", "partner", "dealer", "portal")
 host=reg(urlparse(base).netloc); out=[]; seen=set()
 for a in soup.find_all('a', href=True):
  u=urljoin(base,a['href'])
  txt=a.get_text().lower()
  if u.startswith(("http://","https://")) and reg(urlparse(u).netloc)==host and u not in seen:
   if any(k in u.lower() for k in kws) or any(k in txt for k in kws):
    seen.add(u);out.append(u)
 return out[:MAX_LINKS]

async def scan(session,domain,args):
 start=time.perf_counter(); first=None
 
 # Try HTTPS first, if fails try HTTP, if fails try HTTPS without SSL verification
 urls_to_try = [("https://"+domain, True), ("http://"+domain, True), ("https://"+domain, False)]
 
 for u, verify in urls_to_try:
  x=await fetch(session,u,args.timeout,MAX_HTML_BYTES, verify_ssl=verify)
  if x[0]:
   first=x;break
   
 result={"domain":domain,"final_url":"","http_status":"","cpq_detected":"NO","cpq_vendor":"","confidence":"NOT_DETECTED","score":0,"detection_method":"","evidence":"","scan_time_seconds":0,"error":""}
 
 if not first:
  result["error"]=x[6] if x else "Connection failed"
  return result
  
 _,url,status,html,headers,cookies,_=first
 result.update(final_url=url,http_status=status)
 
 # Parse HTML with BeautifulSoup for cleaner extraction
 soup = BeautifulSoup(html, 'html.parser')
 # Extract visible text
 for script in soup(["script", "style"]):
  script.extract()
 visible_text = soup.get_text(separator=' ')
 
 # We search headers, cookies, visible text, and raw scripts/meta
 raw_meta_scripts = str(soup.find_all(['script', 'meta']))
 search_corpus = visible_text + "\\n" + raw_meta_scripts + "\\n" + headers + "\\n" + cookies + "\\n" + url
 
 hits=detect(search_corpus,"homepage"); generic=bool(re.search(r"\bcpq\b|configure,?\s*price,?\s*quote|product\s*configurator|dealer\s*portal|b2b\s*commerce",visible_text,re.I)); methods=["homepage"]
 
 if args.scan_scripts:
  for su in scripts(url,soup):
   x=await fetch(session,su,args.timeout,MAX_ASSET_BYTES)
   if x[0]:hits+=detect(x[3]+"\n"+x[1],"script")
  methods.append("scripts")
  
 if args.deep_scan:
  for lu in links(url,soup):
   if STOP:break
   x=await fetch(session,lu,args.timeout,MAX_HTML_BYTES)
   if x[0]:
    page_soup = BeautifulSoup(x[3], 'html.parser')
    page_text = page_soup.get_text(separator=' ')
    hits+=detect(page_text+"\n"+str(page_soup.find_all(['script', 'meta']))+"\n"+x[4]+"\n"+x[1],"deep")
    generic=generic or bool(re.search(r"\bcpq\b|configure,?\s*price,?\s*quote|product\s*configurator|dealer\s*portal|b2b\s*commerce",page_text,re.I))
   
  subdomains = ["quote.", "partners.", "shop.", "store.", "b2b.", "portal."]
  async def check_sub(sub):
   su = "https://" + sub + domain
   x = await fetch(session, su, args.timeout, MAX_HTML_BYTES)
   if x[0]:
    psoup = BeautifulSoup(x[3], 'html.parser')
    ptext = psoup.get_text(separator=' ')
    res = detect(ptext+"\n"+str(psoup.find_all(['script', 'meta']))+"\n"+x[4]+"\n"+x[1],"subdomain")
    gen = bool(re.search(r"\bcpq\b|configure,?\s*price,?\s*quote|product\s*configurator|dealer\s*portal|b2b\s*commerce",ptext,re.I))
    return res, gen
   return [], False
   
  sub_results = await asyncio.gather(*[check_sub(sub) for sub in subdomains])
  for s_hits, s_gen in sub_results:
   hits+=s_hits
   generic = generic or s_gen
  methods.append("deep")
  
 merged={}
 for v,s,e in hits:
  if v not in merged:merged[v]=[0,[]]
  merged[v][0]=min(100,merged[v][0]+s); merged[v][1]+=e
  
 if merged:
  v=max(merged,key=lambda z:merged[z][0]); s=merged[v][0]
  result.update(cpq_vendor=v,confidence=conf(s),score=s,evidence=" | ".join(list(dict.fromkeys(merged[v][1]))[:8]))
 elif generic:result.update(cpq_detected="YES",confidence="POSSIBLE",score=15,evidence="Generic CPQ/configure-price-quote language found; vendor not identified")
 
 result["cpq_detected"]="YES" if result["confidence"]!="NOT_DETECTED" else "NO"
 result["detection_method"]=",".join(methods);result["scan_time_seconds"]=round(time.perf_counter()-start,2)
 return result

FIELDS=["domain","final_url","http_status","cpq_detected","cpq_vendor","confidence","score","detection_method","evidence","scan_time_seconds","error"]

def read_domains(path,column):
 with open(path,encoding="utf-8-sig",newline="") as f:
  sample=f.read(8192);f.seek(0)
  try:dialect=csv.Sniffer().sniff(sample,delimiters=",;\t|")
  except csv.Error:dialect=csv.excel
  r=csv.DictReader(f,dialect=dialect); heads=r.fieldnames
  if not heads:raise ValueError("CSV has no header")
  lookup={h.lower().strip():h for h in heads}
  col=column or next((lookup[x] for x in ("domain","domains","website","website_url","url","company_domain","company website") if x in lookup),heads[0])
  seen=set();out=[]
  for row in r:
   d=norm(row.get(col))
   if d and d not in seen:seen.add(d);out.append(d)
 return out,col

def load_done():
 try:
  with open(CHECKPOINT_FILE,encoding="utf-8") as f:return set(json.load(f).get("completed",[]))
 except:return set()

def save_done(done):
 with open(CHECKPOINT_FILE+".tmp","w",encoding="utf-8") as f:json.dump({"completed":sorted(done)},f)
 os.replace(CHECKPOINT_FILE+".tmp",CHECKPOINT_FILE)

def write_rows(rows):
 if not rows:return
 exists=os.path.exists(RESULTS_FILE)
 with open(RESULTS_FILE,"a",encoding="utf-8-sig",newline="") as f:
  w=csv.DictWriter(f,fieldnames=FIELDS)
  if not exists:w.writeheader()
  w.writerows(rows)
 errs=[x for x in rows if x["error"]]
 if errs:
  exists=os.path.exists(ERRORS_FILE)
  with open(ERRORS_FILE,"a",encoding="utf-8-sig",newline="") as f:
   w=csv.DictWriter(f,fieldnames=["domain","final_url","http_status","error"])
   if not exists:w.writeheader()
   for x in errs:w.writerow({k:x[k] for k in ["domain","final_url","http_status","error"]})

async def run(args):
 domains,col=read_domains(args.input,args.column);done=load_done() if args.resume else set();pending=[d for d in domains if d not in done]
 print(f"Domain column: {col}\\nUnique domains: {len(domains):,}\\nRemaining: {len(pending):,}")
 q=asyncio.Queue()
 for d in pending:q.put_nowait(d)
 rows=[];lock=asyncio.Lock();stats={"n":0,"confirmed":0,"likely":0,"possible":0};start=time.perf_counter()
 connector=aiohttp.TCPConnector(limit=max(args.workers*2,20),limit_per_host=3,ttl_dns_cache=300)
 async with aiohttp.ClientSession(connector=connector) as session:
  async def worker():
   while not STOP:
    try:d=q.get_nowait()
    except asyncio.QueueEmpty:return
    try:x=await scan(session,d,args)
    except Exception as e:x={"domain":d,"final_url":"","http_status":"","cpq_detected":"NO","cpq_vendor":"","confidence":"NOT_DETECTED","score":0,"detection_method":"","evidence":"","scan_time_seconds":0,"error":f"{type(e).__name__}: {e}"}
    async with lock:
     rows.append(x);done.add(d);stats["n"]+=1
     if x["confidence"]=="CONFIRMED":stats["confirmed"]+=1
     elif x["confidence"]=="LIKELY":stats["likely"]+=1
     elif x["confidence"]=="POSSIBLE":stats["possible"]+=1
     if len(rows)>=SAVE_EVERY:batch=rows[:];rows.clear();write_rows(batch);save_done(done)
     if stats["n"]%25==0:
      rate=stats["n"]/max(time.perf_counter()-start,.01)
      print(f"\\rProcessed {stats['n']:,}/{len(pending):,} | {rate:.2f}/sec | Confirmed {stats['confirmed']:,} | Likely {stats['likely']:,} | Possible {stats['possible']:,}",end="",flush=True)
    q.task_done();await asyncio.sleep(random.uniform(.02,.12))
  await asyncio.gather(*[asyncio.create_task(worker()) for _ in range(args.workers)])
 if rows:write_rows(rows)
 save_done(done);elapsed=time.perf_counter()-start
 print(f"\\n\\nCOMPLETE\\nProcessed: {stats['n']:,}\\nConfirmed: {stats['confirmed']:,}\\nLikely: {stats['likely']:,}\\nPossible: {stats['possible']:,}\\nElapsed: {elapsed/60:.1f} min\\nResults: {os.path.abspath(RESULTS_FILE)}")
 if STOP:print("Stopped safely. Run again with --resume")

def main():
 p=argparse.ArgumentParser(description="Detect public evidence of CPQ technologies")
 p.add_argument("input");p.add_argument("--column");p.add_argument("--workers",type=int,default=30);p.add_argument("--timeout",type=int,default=20);p.add_argument("--deep-scan",action="store_true");p.add_argument("--no-script-scan",dest="scan_scripts",action="store_false");p.set_defaults(scan_scripts=True);p.add_argument("--resume",action="store_true")
 a=p.parse_args()
 if not os.path.exists(a.input):sys.exit("Input file not found: "+a.input)
 if a.workers<1:sys.exit("--workers must be >= 1")
 asyncio.run(run(a))
if __name__=="__main__":
 try:main()
 except KeyboardInterrupt:print("\\nInterrupted. Run again with --resume.")
