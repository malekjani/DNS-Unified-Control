'use strict';
const engines=['master','slipstream','dnstt','noizdns','vaydns','soar','iodine','dns2tcp','xdns'];
const names={master:'MasterDnsVPN',slipstream:'SlipStream Rust',dnstt:'DNSTT',noizdns:'NoizDNS',vaydns:'VayDNS',soar:'Soar',iodine:'iodine',dns2tcp:'dns2tcp',xdns:'XDNS · Xray'};
const hints={master:'ARQ · Multi-Resolver',slipstream:'QUIC · Rust (archived)',dnstt:'Noise · KCP',noizdns:'DNSTT fork · alternate DNS encoding',vaydns:'KCP/SMUX · DoH/DoT clients',soar:'Multi-path · signed handshake',iodine:'IP over DNS · no encryption',dns2tcp:'TCP over DNS · no encryption',xdns:'Xray FinalMask · TXT/A/AAAA/CNAME'};
const fields={master:['domain','udp_port','arq_window','log_level','encryption_method','client_port'],slipstream:['domain','udp_port','target','dns_listen_host','max_connections','idle_timeout_seconds','client_resolvers','client_authoritative','client_port','client_keep_alive','client_cc'],dnstt:['domain','udp_port','target'],noizdns:['domain','udp_port','target'],vaydns:['domain','udp_port','target','mtu','queue_size','dnstt_compat','record_type','vay_idle_timeout','vay_keepalive','vay_kcp_window','vay_queue_overflow','vay_log_level'],soar:['domain','udp_port','target'],iodine:['domain','udp_port','tunnel_ip'],dns2tcp:['domain','udp_port','target','resource'],xdns:['domain','udp_port','xdns_record_type','xdns_mtu']};
const labels={domain:'زیردامنه اختصاصی (NS)',udp_port:'پورت شنود UDP',arq_window:'ARQ Window',encryption_method:'Encryption Method',log_level:'Log Level',target:'مقصد TCP محلی',tunnel_ip:'IP داخلی TUN',resource:'Resource Name',dns_listen_host:'DNS Listen Host',max_connections:'Max QUIC connections',idle_timeout_seconds:'Idle timeout (s)',client_resolvers:'Resolverهای کلاینت',client_authoritative:'Authoritative endpoints',client_port:'Client TCP Port',client_keep_alive:'Keep-alive (ms)',client_cc:'Congestion Control',mtu:'MTU',queue_size:'Queue size',dnstt_compat:'DNSTT compatibility',record_type:'DNS record type',vay_idle_timeout:'VayDNS Idle Timeout (s)',vay_keepalive:'VayDNS Keepalive (s)',vay_kcp_window:'VayDNS KCP Window',vay_queue_overflow:'VayDNS Overflow Mode',vay_log_level:'VayDNS Log Level',soar_allow_ports:'Deprecated, not used by restricted Soar',xdns_record_type:'FinalMask DNS type (template)',xdns_mtu:'FinalMask MTU (template)'};
const opts={log_level:['DEBUG','INFO','WARN','ERROR'],dns_listen_host:['0.0.0.0','::','127.0.0.1'],client_cc:['auto','bbr','dcubic'],record_type:['txt','a','aaaa','cname'],vay_queue_overflow:['drop','block'],vay_log_level:['debug','info','warning','error'],soar_allow_ports:['80,443','443'],xdns_record_type:['txt','a','aaaa','cname']};
const ints=['udp_port','arq_window','encryption_method','max_connections','idle_timeout_seconds','client_port','client_keep_alive','mtu','queue_size','vay_idle_timeout','vay_keepalive','vay_kcp_window','xdns_mtu'];
const bools=['dnstt_compat'];
let telemetryData=null;let advancedData=null;
let csrf='',status=null,metrics=null,tab='overview',selected='master',dirtyForm=false,securityLoaded=false,history={cpu:[],ram:[],rx:[],tx:[]},lastTraffic=null,busy=false,refreshTimer=null;
const el=id=>document.getElementById(id);
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function byte(n){if(n==null)return '—';const units=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(i?1:0)+' '+units[i];}
function flash(msg,error=false){const node=el('flash');node.textContent=msg;node.classList.remove('hidden');node.classList.toggle('error',error);}
function clearFlash(){el('flash').classList.add('hidden');}
async function api(url,method='GET',data){const headers={'Accept':'application/json'};if(method!=='GET'){headers['Content-Type']='application/json';headers['X-CSRF-Token']=csrf;}const r=await fetch(url,{method,credentials:'same-origin',headers,body:data===undefined?undefined:JSON.stringify(data)});let v;try{v=await r.json()}catch{v={detail:'Server response was not JSON'}}if(!r.ok)throw new Error(typeof v.detail==='string'?v.detail:JSON.stringify(v.detail??v));return v;}
async function boot(){try{const s=await api('/api/session');csrf=s.csrf||'';if(s.stage==='full'){showApp();await update();poll()}else{showAuthStep(s.stage||'login')}}catch(e){showAuthStep('login');el('login-error').textContent=e.message}}
function showAuthStep(stage){el('login').classList.remove('hidden');el('app').classList.add('hidden');if(refreshTimer)clearInterval(refreshTimer);for(const id of ['login-form','mfa-enroll','mfa-verify-form','recovery-display'])el(id).classList.add('hidden');const map={login:'login-form',enroll:'mfa-enroll',challenge:'mfa-verify-form',recovery:'recovery-display'};el(map[stage]||map.login).classList.remove('hidden');el('login-error').textContent=''}
function showLogin(){csrf='';for(const id of ['mfa-secret','recovery-codes','activation-code','mfa-code']){const n=el(id);if(n){if(n.tagName==='INPUT')n.value='';else n.textContent=''}}el('qr-image').removeAttribute('src');el('mfa-setup-details').classList.add('hidden');showAuthStep('login')}
function showApp(){el('login').classList.add('hidden');el('app').classList.remove('hidden');el('nav-host').textContent=location.hostname;}
function showRecovery(codes){el('recovery-codes').textContent=codes.join('\n');showAuthStep('recovery')}
async function startMfaEnrollment(){try{const r=await api('/api/mfa/setup','POST',{});el('mfa-secret').textContent=r.secret;el('qr-image').src=r.qr_path+'?'+Date.now();el('mfa-setup-details').classList.remove('hidden')}catch(e){el('login-error').textContent=e.message}}
async function finishFullLogin(r){csrf=r.csrf;showApp();securityLoaded=false;await update();poll();if(r.used_recovery)flash('برای این ورود از کد بازیابی استفاده شد. کدهای باقی‌مانده را بررسی کن.');}
async function renderSecurity(){try{const x=await api('/api/mfa/status');const node=el('security');node.innerHTML=`<div class="panel"><h2>احراز هویت دومرحله‌ای (TOTP)</h2><div class="notice">فعال · کد شش‌رقمی ۳۰ثانیه‌ای · سازگار با Aegis و Google Authenticator</div><div class="kv"><span class="label">تعداد کدهای بازیابی استفاده‌نشده</span><strong>${Number(x.recovery_codes_remaining)}</strong></div><p class="muted-block">برای تولید کدهای بازیابی جدید، یک کد تازه از اپلیکیشن احراز هویت وارد کن. با این عملیات، تمام کدهای بازیابی قبلی باطل می‌شوند.</p><form id="mfa-rotate-form"><label for="rotate-code" class="field">کد TOTP جدید<input id="rotate-code" name="code" maxlength="6" pattern="[0-9]{6}" required autocomplete="one-time-code" dir="ltr"></label><button class="btn primary" type="submit">بازسازی کدهای بازیابی</button></form><p class="dim">غیرفعال‌سازی MFA از داخل پنل مجاز نیست. بازیابی اضطراری فقط با دسترسی root در VPS انجام می‌شود.</p></div>`}catch(e){el('security').textContent='خطا در وضعیت امنیت: '+e.message;securityLoaded=false}}
function poll(){if(refreshTimer)clearInterval(refreshTimer);refreshTimer=setInterval(()=>{if(!busy)update(true)},3500)}
async function update(silent=false){try{const [s,m]=await Promise.all([api('/api/status'),api('/api/metrics')]);status=s;metrics=m;el('connection').textContent='Agent متصل';document.querySelector('.status-dot').classList.add('ok');const now=Date.now();if(lastTraffic&&m.time>lastTraffic.time){const dt=m.time-lastTraffic.time;push('rx',Math.max(0,(m.net_recv-lastTraffic.rx)/dt));push('tx',Math.max(0,(m.net_sent-lastTraffic.tx)/dt));}lastTraffic={time:m.time,rx:m.net_recv,tx:m.net_sent};push('cpu',m.cpu);push('ram',m.ram_percent);render();}catch(e){el('connection').textContent='قطع ارتباط Agent';document.querySelector('.status-dot').classList.remove('ok');if(!silent)flash(e.message,true)}}
function push(k,v){history[k].push(v);if(history[k].length>42)history[k].shift()}
function spark(arr,color='#50c7b0',max){const data=arr.length>1?arr:[0,0];const ceiling=Math.max(max||0,...data,1);const points=data.map((v,i)=>(i/(data.length-1)*600).toFixed(1)+','+(105-v/ceiling*90).toFixed(1)).join(' ');return `<svg class="spark" viewBox="0 0 600 116" preserveAspectRatio="none" role="img" aria-label="نمودار نمونه‌های اخیر"><path d="M0 105 H600 M0 55 H600 M0 10 H600" stroke="#28364b" stroke-width="1"/><polyline points="${points}" stroke="${color}" stroke-width="2.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`}
function badge(what){return `<span class="badge ${what?'live':'bad'}">${what?'فعال':'متوقف'}</span>`}
function headerStatus(){return `<div class="notice ${status.active.length>1?'switch-warning':''}">${status.active.length>1?'هشدار: چند موتور فعال هستند؛ باید وضعیت سرویس‌ها اصلاح شود.':status.active.length===1?'Exclusive Mode — فقط یک موتور روی سرور فعال است.':'هیچ موتور تونلی روی سرور فعال نیست.'} <strong>${status.active.map(e=>names[e]).join(' · ')||''}</strong></div>`}
function render(){if(!status)return;document.querySelectorAll('#nav button').forEach(x=>x.classList.toggle('selected',x.dataset.tab===tab));const titles={workflow:'کلاینت‌های موتور DNS',dante:'Shared Dante · SOCKS5',setup:'نصب و سلامت سرور',overview:'داشبورد',engines:'موتورهای تونل',monitor:'مانیتورینگ زنده',logs:'گزارش‌ها و رویدادها',settings:'پیکربندی',dns:'رکوردهای DNS',methods:'طبقه‌بندی روش‌ها',security:'امنیت و ورود دو مرحله‌ای'};el('page-title').textContent=titles[tab];document.querySelectorAll('section.page').forEach(x=>x.classList.toggle('hidden',x.id!==tab));if(tab==='workflow' && !workflowLoaded){loadWorkflow()}if(tab==='dante' && !danteLoaded){loadDante()}if(tab==='setup' && !setupLoaded){loadSetup()}if(tab==='security' && !securityLoaded){securityLoaded=true;renderSecurity()}if(tab==='dns' && !document.activeElement?.closest('#cf-form'))renderDns();if(tab==='methods')renderMethods();if(tab==='overview'){renderOverview();renderReadiness();refreshReadinessIfNeeded();}if(tab==='engines')renderEngines();if(tab==='monitor' && document.activeElement?.id!=='client-report-json')renderMonitor();if(tab==='logs' && document.getElementById('journal-area')?.dataset.engine!==selected)renderLogs();if(tab==='settings' && !dirtyForm && !(document.activeElement?.matches('input, select')))renderSettings();}
function renderOverview(){const active=status.active.map(e=>names[e]).join(' + ')||'None';const rate=history.rx.at(-1);const cpu=metrics?.cpu;el('overview').innerHTML=`<div class="grid metrics"><div class="panel"><div class="metric-title">موتور فعال</div><div class="metric-value" style="font-size:20px">${esc(active)}</div><div class="metric-sub">وضعیت واقعی systemd</div></div><div class="panel"><div class="metric-title">مصرف CPU</div><div class="metric-value">${cpu===undefined?'—':cpu.toFixed(1)+'%'}</div><div class="metric-sub">کل سرور</div></div><div class="panel"><div class="metric-title">حافظه RAM</div><div class="metric-value">${metrics?metrics.ram_percent.toFixed(1)+'%':'—'}</div><div class="metric-sub">${metrics?byte(metrics.ram_used)+' / '+byte(metrics.ram_total):'—'}</div></div><div class="panel"><div class="metric-title">دریافت شبکه سرور</div><div class="metric-value">${rate==null?'—':byte(rate)+'/s'}</div><div class="metric-sub">کل اینترفیس‌ها، نه فقط تونل</div></div></div><div class="spaced">${headerStatus()}</div><div class="grid columns"><div class="panel"><h2>مصرف CPU — نمونه‌های اخیر</h2>${spark(history.cpu)}<div class="dim" style="font-size:11px">اندازه‌گیری هر ۳٫۵ ثانیه؛ نمودار از زمان بازشدن پنل</div></div><div class="panel"><h2>کنترل سریع</h2><div class="muted-block">از بخش «موتورهای تونل» می‌توانی سرویس موردنظر را راه‌اندازی کنی. هنگام سوییچ اتصال‌های جاری قطع می‌شوند.</div><div class="engine-actions"><button class="btn primary" data-go="engines">انتخاب موتور</button><button class="btn" data-go="workflow">ساخت کلاینت</button><button class="btn" data-go="dante">تنظیمات Dante</button><button class="btn danger" data-stop="1" ${status.active.length?'':'disabled'}>توقف همه تونل‌ها</button></div></div></div><div class="panel spaced" style="margin-top:17px"><h2>وضعیت سرویس‌ها</h2>${engines.map(e=>`<div class="engine-line"><div><div class="engine-name">${esc(names[e])}</div><div class="engine-hint">${esc(hints[e])}</div></div><div>${badge(status.engines[e].unit.active)}</div></div>`).join('')}</div>`}
function renderEngines(){el('engines').innerHTML=`<div class="notice spaced">تنها سرویس‌های <code>dns-unified@ENGINE.service</code> کنترل می‌شوند. وضعیت «آماده» صرفاً به‌معنی نصب باینری و فایل‌های پیش‌نیاز است، نه تضمین عبور ترافیک.</div><div class="engine-grid">${engines.map(e=>{const o=status.engines[e],pre=o.preflight;return `<article class="panel engine-card ${o.unit.active?'live':''}"><div class="engine-head"><div class="engine-symbol">◈</div><div style="flex:1"><div class="engine-title">${esc(names[e])}</div><div class="engine-hint">${esc(hints[e])}</div></div>${badge(o.unit.active)}</div><div class="kv"><span class="label">آمادگی اجرا</span><span class="${pre.ready?'good-text':'danger-text'}">${pre.ready?'آماده':'نیاز به تنظیم'}</span></div><div class="kv"><span class="label">دامنه</span><span class="mono">${esc(o.config.domain)}</span></div>${!pre.ready?`<div class="reasons">${pre.issues.map(z=>'• '+esc(z)).join('<br>')}</div>`:''}<div class="engine-actions"><button class="btn primary small" data-${o.unit.active?'restart':'switch'}="${e}" ${!pre.ready||busy?'disabled':''}>${o.unit.active?'راه‌اندازی مجدد':'فعال‌سازی'}</button><button class="btn small subtle" data-edit="${e}">تنظیم آرگومان‌ها</button><button class="btn small subtle" data-log="${e}">لاگ‌ها</button></div></article>`}).join('')}</div><div class="panel" style="margin-top:16px"><h3>توقف تمام موتورها</h3><p class="muted-block">این عملیات همه سرویس‌های تونل را خاموش می‌کند ولی روی پنل مدیریت یا SSH اثری نمی‌گذارد.</p><button class="btn danger" data-stop="1" ${status.active.length?'':'disabled'}>توقف همه</button></div>`}
function renderMonitor(){const p=metrics||{};const proc=(p.processes||[]).map(x=>`<div class="kv"><span class="label">${esc(names[x.engine])} PID ${x.pid}</span><span>${x.cpu_percent.toFixed(1)}% CPU · ${byte(x.rss)} RAM</span></div>`).join('');el('monitor').innerHTML=`<div class="grid metrics"><div class="panel"><div class="metric-title">CPU</div><div class="metric-value">${(p.cpu??0).toFixed(1)}%</div><div class="progress"><div style="width:${p.cpu??0}%"></div></div></div><div class="panel"><div class="metric-title">RAM</div><div class="metric-value">${(p.ram_percent??0).toFixed(1)}%</div><div class="progress"><div style="width:${p.ram_percent??0}%"></div></div></div><div class="panel"><div class="metric-title">DISK</div><div class="metric-value">${(p.disk_percent??0).toFixed(1)}%</div><div class="progress"><div style="width:${p.disk_percent??0}%"></div></div></div><div class="panel"><div class="metric-title">پورت ۵۳ DNS</div><div class="metric-value" style="font-size:19px">${p.port53?.length?'در حال استفاده':'آزاد'}</div><div class="metric-sub mono">${esc((p.port53||[]).join(', '))}</div></div></div><div class="grid columns"><div class="panel"><h2>شبکه — کل سرور</h2>${spark(history.rx,'#50c7b0')}<div class="kv"><span class="label">دریافت کنونی</span><b>${history.rx.length?byte(history.rx.at(-1))+'/s':'—'}</b></div>${spark(history.tx,'#8eb5ff')}<div class="kv"><span class="label">ارسال کنونی</span><b>${history.tx.length?byte(history.tx.at(-1))+'/s':'—'}</b></div></div><div class="panel"><h2>CPU و RAM</h2><div class="label">CPU</div>${spark(history.cpu,'#f1b862',100)}<div class="label">RAM</div>${spark(history.ram,'#8eb5ff',100)}</div></div><div class="panel" style="margin-top:16px"><h2>منابع موتور فعال</h2>${proc||'<span class="dim">هیچ پردازش فعالی پیدا نشد</span>'}</div><div class="notice" style="margin-top:16px">CPU و RX/TX از کل VPS است، نه فقط موتور فعال. مقادیر RTT، نرخ شکست درخواست و HTTP Throughput زیر فقط از گزارش Probe واقعی روی کلاینت دریافت می‌شوند؛ نرخ شکست درخواست برابر Packet Loss خام DNS نیست.</div><div class="panel" style="margin-top:16px"><h2>اندازه‌گیری واقعی کلاینت</h2>${Object.values(telemetryData?.latest||{}).map(r=>`<div class="kv"><span class="label">${esc(names[r.engine]||r.engine)} · ${esc(r.timestamp)}</span><b>RTT ${esc(r.socks_connect_rtt_ms??'—')} ms · شکست درخواست ${esc(r.request_failure_pct)}% · HTTP ${esc(r.http_throughput_bps??'—')} B/s ${r.icmp_packet_loss_pct!=null?' · ICMP loss '+esc(r.icmp_packet_loss_pct)+'%':''}</b></div>`).join('')||'<p class="dim">هنوز گزارش آزمایش واقعی وارد نشده است.</p>'}<p class="dim">گزارش JSON تولیدشده با اسکریپت duc_socks_probe.py را اینجا جایگذاری کن؛ این فایل شامل رمز نیست.</p><textarea id="client-report-json" rows="5" placeholder="Paste field probe JSON (no credentials)" dir="ltr"></textarea><div class="engine-actions"><button id="telemetry-import" class="btn primary small">ثبت نتیجه واقعی</button></div></div>`}
function renderLogs(){const tabbuttons=engines.map(e=>`<button data-log="${e}" class="${selected===e?'sel':''}">${esc(names[e])}</button>`).join('');el('logs').innerHTML=`<div class="panel"><div class="tabs">${tabbuttons}</div><div id="journal-area" data-engine="${selected}" class="log mono">برای دریافت لاگ موتور انتخاب‌شده، روی «خواندن لاگ» بزن.</div><div class="engine-actions"><button class="btn small" id="get-logs">خواندن لاگ</button></div></div><div class="panel" style="margin-top:16px"><h2>تاریخچه عملیات</h2><table class="table"><thead><tr><th>زمان</th><th>عملیات</th><th>از ← به</th><th>نتیجه</th></tr></thead><tbody>${status.audit.map(a=>`<tr><td>${new Date(a.time*1000).toLocaleString('fa-IR')}</td><td>${esc(a.action)}</td><td>${esc(a.from.join(',')||'none')} ← ${esc(a.to.join(',')||'none')}</td><td>${esc(a.result).slice(0,130)}</td></tr>`).join('')||'<tr><td colspan="4" class="dim">هنوز عملیاتی ثبت نشده است</td></tr>'}</tbody></table></div>`}
function settingInput(k,v){
  if(bools.includes(k))return `<input type="checkbox" name="${k}" ${v?'checked':''}>`;
  if(opts[k])return `<select name="${k}">${opts[k].map(x=>`<option value="${esc(x)}" ${v===x?'selected':''}>${esc(x)}</option>`).join('')}</select>`;
  return `<input name="${k}" value="${esc(v)}" dir="ltr" ${ints.includes(k)?'type="number"':''} ${k==='client_authoritative'?'':'required'}>`;
}
function renderSettings(){
 const e=selected,o=status.engines[e],f=fields[e];
 el('settings').innerHTML=`<div class="panel spaced"><h2>تنظیمات ${esc(names[e])}</h2><div class="tabs">${engines.map(x=>`<button data-edit="${x}" class="${x===selected?'sel':''}">${esc(names[x])}</button>`).join('')}</div><form id="profile-form"><div class="form-grid">${f.map(k=>`<label class="field">${esc(labels[k])}${settingInput(k,o.config[k])}</label>`).join('')}</div><div class="form-actions"><button class="btn primary" type="submit">ذخیره تنظیمات</button></div></form><div class="notice">هر موتور زیردامنه مستقل دارد؛ ذخیره فرم موتور فعال را restart نمی‌کند. فیلدهای کلاینت فقط قالب هستند و اجرای کلاینت روی VPS صورت نمی‌گیرد.</div>${e==='slipstream'?`<h3>دستور کلاینت Rust</h3><pre class="log mono" style="white-space:pre-wrap;overflow-wrap:anywhere">${esc(rustClientCommand(o.config))}</pre><button class="btn small" data-copy-rust="1">کپی دستور</button>${renderSlipstreamClientHelp(o.config)}`:''}${e==='xdns'?'<div class="notice">XDNS زیرمجموعه Xray FinalMask است؛ باید config واقعی Xray را در /etc/dns-unified/engines/xdns/server.json قرار داده و xray run -test اجرا شود. این فیلدها به‌تنهایی JSON عملیاتی تولید نمی‌کنند.</div>':''}${e==='noizdns'?'<div class="notice">سرور NoizDNS در نصب/ارتقا آماده شده است. پنل ZIP رسمی SlipNet CLI را با SHA-256 معتبر و پروفایل sayedns / Stealth تولید می‌کند؛ هنوز تأیید اتصال زنده Dante لازم است. رمز Dante در ZIP قرار نمی‌گیرد.</div>':''}</div><div class="panel"><h2>شرایط سرویس</h2><div class="notice">${esc((o.preflight.issues||[]).join(' | ')||'Preflight فایل‌ها و باینری موفق بوده؛ اتصال واقعی تأیید نشده است.')}</div><div class="muted-block">سرویس‌های تونل تنها از طریق Agent خصوصی و پس از اعتبارسنجی اجرا می‌شوند. DNS رکوردها جدا می‌مانند و تغییر موتور آنها را حذف نمی‌کند.</div></div>`;
}
// Cloudflare is explicit opt-in: the token exists only in this form and request.
function appendCloudflareForm(){
 const zone=(status?.engines?.dnstt?.config?.domain||'d.example.com').split('.').slice(1).join('.');
 const node=el('dns');
 node.insertAdjacentHTML('beforeend',`<div class="panel" style="margin-top:16px"><h2>ساخت/تأیید رکوردهای Cloudflare از داخل پنل</h2>
 <div class="notice">دسترسی لازم: Zone Read و DNS Edit، فقط برای همین دامنه. توکن فقط برای یک درخواست ارسال می‌شود، در پنل یا فایل ذخیره نمی‌شود. اول «پیش‌نمایش» را اجرا کن.</div>
 <form id="cf-form" autocomplete="off"><div class="form-grid">
 <label class="field">Zone (دامنه اصلی)<input name="domain" dir="ltr" required value="${esc(zone)}"></label>
 <label class="field">IP عمومی VPS<input name="ipv4" dir="ltr" required placeholder="Public IPv4"></label>
 <label class="field">API Token موقت<input name="token" type="password" dir="ltr" required autocomplete="off" placeholder="Zone-scoped token"></label>
 </div><div class="engine-actions"><button class="btn" type="submit" name="action" value="preview">پیش‌نمایش ۱۰ رکورد</button>
 <button class="btn primary" type="submit" name="action" value="apply">اعمال تغییرات Cloudflare</button></div></form>
 <pre id="cf-result" class="log mono">برای شروع، توکن را وارد کن و پیش‌نمایش را بزن.</pre>
 <p class="dim">این بخش رکوردهای A/NS را تغییر می‌دهد؛ گواهی HTTPS و سرویس تونل را خودکار نصب/فعال نمی‌کند. روی سرویس فعال، مهاجرت Zone محدود می‌شود.</p>
 </div>`);
}
function renderDns(){
 const rows=engines.map(e=>{const item=status.engines[e];return `<tr><td>${esc(names[e])}</td><td><code>NS</code></td><td class="mono">${esc(item.config.domain)}</td><td class="mono">${esc("ns."+item.config.domain.split(".").slice(1).join("."))}</td><td>${item.unit.active?'فعال':'مستقل / آماده انتخاب'}</td></tr>`}).join('');
 el('dns').innerHTML=`<div class="panel"><h2>تفویض جداگانه هر موتور</h2><div class="notice">این جدول بر اساس پروفایل‌های ذخیره‌شده است؛ به معنای تأیید انتشار DNS در Cloudflare نیست.</div><div style="overflow-x:auto"><table class="table"><thead><tr><th>هسته</th><th>Type</th><th>Name</th><th>Target</th><th>Service</th></tr></thead><tbody>${rows}</tbody></table></div><div class="muted-block">رکورد مشترک A: <code>ns.DOMAIN</code> → IPv4 خارجی سرور، DNS Only. از فرم پایین می‌توانی بدون ذخیره دائمی توکن، رکوردهای هر ۹ موتور را بسازی.</div><h3>بررسی واگذاری DNS در Resolverها</h3><button class="btn small" id="check-dns" type="button">بررسی ۹ زیردامنه (Cloudflare/Google)</button><div id="dns-check-results" class="muted-block">بررسی به‌صورت دستی انجام می‌شود؛ این تست اتصال کلاینت به تونل نیست.</div><h3>تنظیم خودکار</h3><pre class="log mono">sudo env PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.cloudflare_dns --domain YOUR_DOMAIN --ip SERVER_IP</pre></div>`;
 appendCloudflareForm();
}
async function loadAdvancedOptions(){
 try{advancedData=await api('/api/workflow/advanced');if(tab==='methods')renderMethods()}
 catch(e){if(tab==='methods')flash('لیست آرگومان‌ها: '+e.message,true)}
}
function renderMethods(){
 const rows=engines.map(e=>{const info=status.catalog?.[e]||{};return `<div class="engine-line"><div><div class="engine-name">${esc(names[e])}</div><div class="engine-hint">${esc(info.family||hints[e])}</div><div class="dim">${esc((info.methods||[]).join(' · '))}</div></div><button class="btn small subtle" data-edit="${e}">آرگومان‌ها</button></div>`}).join('');
 el('methods').innerHTML=`<div class="panel"><h2>هسته‌ها و روش‌های قابل استفاده</h2>${rows}</div><div class="notice">TXT/CNAME نوع رکورد DNS هستند؛ DoH/DoT/DoQ پروتکل انتقال DNS هستند و مستقل از نوع هسته دسته‌بندی می‌شوند. پشتیبانی با نسخه نصب‌شده باید کنترل شود.</div>${renderSlipstreamClientHelp(status.engines.slipstream.config)}<div class="panel spaced"><h2>گزینه‌های عملیاتی و قابلیت‌های بررسی‌نشده</h2>${Object.values(advancedData?.engines||{}).map(x=>`<div class="kv"><span class="label">${esc(names[x.engine])}</span><span>Server: ${esc(x.server_operational.join(', ')||'نیازمند آداپتور')}<br>Client: ${esc(x.client_operational_or_documented.join(', ')||'نیازمند بررسی')}</span></div><p class="dim">${esc(x.note||'')}</p>`).join('')||'<p class="dim">در حال دریافت منابع مستندات...</p>'}</div>`;
}
// Display-only client command. The client binary forwards local TCP, not SOCKS5.
function shellq(s){return "'"+String(s).replace(/'/g,"'\\''")+"'";}
function rustClientCommand(c){
  const args=['./slipstream-rust-client','--domain',c.domain,'--tcp-listen-host','127.0.0.1',
    '--tcp-listen-port',String(c.client_port),'--keep-alive-interval',String(c.client_keep_alive),
    '--cert','./slipstream-rust.crt'];
  if(c.client_cc!=='auto')args.push('--congestion-control',c.client_cc);
  for(const addr of (c.client_resolvers||'').split(',').filter(Boolean))args.push('--resolver',addr);
  for(const addr of (c.client_authoritative||'').split(',').filter(Boolean))args.push('--authoritative',addr);
  return args.map(shellq).join(' ');
}
// Educational help only; it never creates a separate proxy or changes UDP/53.
function renderSlipstreamClientHelp(c){
 const rows=[
   ['--resolver, -r','Recursive DNS: e.g. Cloudflare, repeatable for multipath','1.1.1.1:53'],
   ['--authoritative','Direct DNS server endpoint (NOT 1.1.1.1)','SERVER_IPV4:53'],
   ['--domain, -d','دامنه واگذارشده / delegated zone',c.domain],
   ['--tcp-listen-host','Client local bind — loopback recommended','127.0.0.1'],
   ['--tcp-listen-port, -l','Local raw TCP forwarding port (not automatically SOCKS5)',String(c.client_port)],
   ['--cert','Public TLS certificate for pinning (never the server private key)','./slipstream-rust.crt'],
   ['--congestion-control, -c','auto (omit flag), bbr or dcubic',String(c.client_cc||'auto')],
   ['--keep-alive-interval, -t','Keep-alive interval in milliseconds',String(c.client_keep_alive||400)],
   ['--gso','Experimental / not fully implemented in Rust: left OFF','disabled']
 ];
 const optTable=`<div style="overflow-x:auto"><table class="table"><thead><tr><th>Option</th><th>توضیح / Description</th><th>مثال / Value</th></tr></thead><tbody>${rows.map(([k,d,v])=>`<tr><td class="mono" dir="ltr">${esc(k)}</td><td>${esc(d)}</td><td class="mono" dir="ltr">${esc(v)}</td></tr>`).join('')}</tbody></table></div>`;
 const target=String(c.target||'127.0.0.1:22');
 const ssh=target==='127.0.0.1:22';
 const otherNotice=ssh?'Backend فعلی SSH است؛ از بخش Dante می‌توان SOCKS5 امن را نصب کرد.':target==='127.0.0.1:1080'?'Backend فعلی Dante SOCKS5 با احراز هویت است؛ در v2rayN اطلاعات کاربری را وارد کن.':'پورت هدف سفارشی است؛ وجود سرویس محلی و احراز هویت را بررسی کن.';
 const vport=Number(c.client_port||7000);
 const sshCmd=`ssh -vv -o BatchMode=yes -o PreferredAuthentications=none -o ConnectTimeout=30 -p ${vport} root@127.0.0.1`;
 const proxyCmd=`ssh -N -D 127.0.0.1:1080 -p ${vport} YOUR_SSH_USER@127.0.0.1`;
 return `<div class="panel" style="margin-top:14px"><h2>SlipStream — Client Options / گزینه‌های کلاینت</h2>
   ${optTable}
   <div class="notice">--resolver → Recursive DNS مانند 1.1.1.1:53؛ --authoritative → DNS خود VPS مانند SERVER_IPV4:53. استفاده از --authoritative 1.1.1.1:53 نادرست است. گزینه GSO در این نسخه عمداً فعال نمی‌شود.</div>
   <h2>Using the Tunnel / روش استفاده</h2>
   <p class="dim">TCP target: <code dir="ltr">${esc(target)}</code> · ${esc(otherNotice)}</p>
   <h3>SSH mode (current: ${ssh?'YES':'NO'})</h3>
   <p class="dim">Client-first SSH handshake works; ssh-keyscan/server-first may time out with this pinned Rust release.</p>
   <pre class="log mono" dir="ltr">${esc(sshCmd)}
# After valid SSH authentication:
${esc(proxyCmd)}</pre>
   <h3>SOCKS5 mode (requires a separate secure backend)</h3>
   <p class="dim">Install authenticated loopback-only Dante from the workflow card; activate SOCKS5 backend from the same card. Local TCP forward then carries authenticated SOCKS5. Generate the client URI as root on VPS; do not share it publicly.</p>
   <pre class="log mono" dir="ltr">${esc(`curl --max-time 60 --socks5-hostname 127.0.0.1:${vport} --proxy-user USER:PASS https://api.ipify.org`)}</pre>
   <h3>Shadowsocks mode (requires an independent TCP-only ss-server)</h3>
   <p class="dim">Server target: 127.0.0.1:8388 after explicit configuration. ss-local on the client must point its server_port to the SlipStream LOCAL TCP port ${vport}. The SlipStream client itself is NOT a SOCKS proxy; do not use the upstream example --listen / --socks5-proxy literally.</p>
   <pre class="log mono" dir="ltr">${esc(`{ "server":"127.0.0.1", "server_port":${vport}, "local_address":"127.0.0.1", "local_port":10800, "method":"aes-256-gcm", "password":"REPLACE_SECURELY" }
ss-local -c ./ss-client.json`)}</pre>
   <p class="dim">Dante is now a DUC-managed authenticated localhost backend. It never binds UDP/53 or changes NAT/firewall. Shadowsocks remains manual.</p></div>`;
}
async function switchTo(engine,restart=false){const name=engine==='none'?'توقف همه موتورهای تونل':restart?`راه‌اندازی مجدد ${names[engine]}`:`سوییچ به ${names[engine]}`;if(!confirm(`آیا از ${name} اطمینان داری؟\nاتصال‌های جاری قطع خواهند شد و کلاینت هم باید همان موتور را انتخاب کند.`))return;busy=true;flash('در حال اجرای تغییر...');try{const r=await api('/api/switch','POST',{engine,restart});if(!r.ok)flash((r.error||r.issues?.join('\n')||'سوییچ ناموفق بود')+'\nمرحله: '+r.stage+'\nبازگردانی: '+(r.restored?.join(', ')||'—'),true);else flash('عملیات انجام شد: '+r.stage+'\n'+(r.warning||''));await update(true);}catch(e){flash(e.message,true)}finally{busy=false}}
async function saveProfile(form){const data={};for(const k of fields[selected]){const v=new FormData(form).get(k);data[k]=bools.includes(k)?form.elements[k].checked:ints.includes(k)?Number(v):v;}busy=true;try{const r=await api('/api/profile/'+selected,'POST',{values:data});dirtyForm=false;flash('تنظیمات ذخیره شد. '+(r.restart_required?'برای اعمال باید سرویس فعال را مجدداً راه‌اندازی کنی.':''));await update(true);}catch(e){flash(e.message,true)}finally{busy=false}}
async function checkDns(){
 const node=el('dns-check-results');if(!node)return;
 node.textContent='در حال استعلام NS از Nameserver مرجع و A از دو Resolver عمومی...';
 try{const report=await api('/api/dns/check');
   const updated=el('dns-check-results');if(!updated)return;
   updated.innerHTML=`<p><b>${report.verified} / ${report.total}</b> واگذاری تأییدشده در Nameserver مرجع و Resolverها</p>`+
      `<div style="overflow-x:auto"><table class="table"><thead><tr><th>موتور</th><th>نام NS</th><th>وضعیت</th></tr></thead><tbody>`+
      report.checks.map(c=>`<tr><td>${esc(names[c.engine]||c.engine)}</td><td class="mono">${esc(c.target||'—')}</td><td>${c.delegated?'درست':'نیاز به بررسی'} ${esc(c.note||'')}</td></tr>`).join('')+
      `</tbody></table></div><small>صرفاً مشاهده واگذاری در DNSهای عمومی؛ عبور واقعی تونل از شبکه کاربر تأیید نمی‌شود.</small>`;
 }catch(e){const n=el('dns-check-results');if(n)n.textContent=e.message;}
}
async function loadLogs(){const node=el('journal-area');if(!node)return;node.textContent='در حال دریافت...';try{const x=await api('/api/logs/'+selected);const now=el('journal-area');if(now)now.textContent=x.lines||'لاگی پیدا نشد';}catch(e){const now=el('journal-area');if(now)now.textContent=e.message}}
let workflowEverOpened=false;
function navigate(t){if(t==='workflow' && !workflowEverOpened){selected=status?.active?.[0]||selected;workflowEverOpened=true}tab=t;dirtyForm=false;workflowLoaded=false;danteLoaded=false;setupLoaded=false;if(t==='monitor')loadClientTelemetry();if(t==='methods')loadAdvancedOptions();if(workflowTimer)clearTimeout(workflowTimer);clearFlash();render()}
document.addEventListener('click',async ev=>{const b=ev.target.closest('button');if(!b)return;if(b.dataset.copyRust){if(status?.engines?.slipstream){try{await navigator.clipboard.writeText(rustClientCommand(status.engines.slipstream.config));flash('دستور کلاینت کپی شد.')}catch(e){flash('دسترسی clipboard ممکن نیست؛ دستور را از صفحه انتخاب و کپی کن.',true)}}return}if(b.dataset.tab){navigate(b.dataset.tab);return}if(b.dataset.go){navigate(b.dataset.go);return}if(b.dataset.edit){selected=b.dataset.edit;dirtyForm=false;navigate('settings');return}if(b.dataset.log){selected=b.dataset.log;navigate('logs');return}if(b.dataset.switch){await switchTo(b.dataset.switch);return}if(b.dataset.restart){await switchTo(b.dataset.restart,true);return}if(b.dataset.stop){await switchTo('none');return}if(b.id==='wf-shared-install'){await installDanteWeb();return}if(b.id==='wf-shared-attach'){await sharedBackendWeb('dante');return}if(b.id==='wf-shared-restore'){await sharedBackendWeb('restore');return}if(b.id==='wf-shared-custom'){await customBackendWeb();return}if(b.id==='telemetry-import'){await importClientReport();return}if(b.id==='wf-dante-install'){await installDanteWeb();return}if(b.id==='wf-dante-activate'){await activateDanteWeb('socks5');return}if(b.id==='wf-dante-ssh'){await activateDanteWeb('ssh');return}if(b.id==='wf-refresh'){await loadWorkflow();return}if(b.id==='dante-refresh'){await loadDante();return}if(b.id==='soar-build'){await startWfJob('build-client');return}if(b.id==='wf-build'){await startWfJob(workflowChoices?.choices?.find(x=>x.id===selectedClientKind)?.kind==='alternate'?'build-alternate':'build-client');return}if(b.id==='wf-install'){await startWfJob('install-server');return}if(b.id==='wf-copy'){try{await navigator.clipboard.writeText(el('wf-command')?.textContent||'');flash('دستور کلاینت کپی شد')}catch(e){flash('دسترسی Clipboard ممکن نیست',true)}return}if(b.id==='get-logs'){await loadLogs();return}if(b.id==='check-dns'){await checkDns();return}if(b.id==='start-enroll'){await startMfaEnrollment();return}if(b.id==='copy-recovery'){try{await navigator.clipboard.writeText(el('recovery-codes').textContent)}catch(e){el('login-error').textContent='کپی انجام نشد؛ کدها را دستی ذخیره کن'}return}if(b.id==='recovery-done'){el('recovery-codes').textContent='';await finishFullLogin({csrf});return}if(b.id==='refresh'){await update();return}if(b.id==='logout'){try{await api('/api/logout','POST',{})}catch{}showLogin();}});
document.addEventListener('change',ev=>{if(ev.target.id==='workflow-engine'){selected=ev.target.value;selectedClientKind='';workflowLoaded=false;loadWorkflow()}if(ev.target.id==='setup-engine'){selected=ev.target.value;setupLoaded=false;loadSetup()}if(ev.target.name==='client-choice'){selectedClientKind=ev.target.value;drawWorkflow(el('wf-resolver')?.value||'1.1.1.1:53',Number(el('wf-port')?.value||2080))}});document.addEventListener('input',ev=>{if(ev.target.closest('#profile-form'))dirtyForm=true});
document.addEventListener('submit',async ev=>{if(ev.target.id==='login-form'){ev.preventDefault();el('login-error').textContent='';try{const r=await api('/api/login','POST',{password:el('password').value});csrf=r.csrf;el('password').value='';showAuthStep(r.stage)}catch(e){el('login-error').textContent=e.message}}else if(ev.target.id==='mfa-activate-form'){ev.preventDefault();try{const r=await api('/api/mfa/activate','POST',{code:el('activation-code').value});csrf=r.csrf;el('activation-code').value='';el('mfa-secret').textContent='';el('qr-image').removeAttribute('src');showRecovery(r.recovery_codes)}catch(e){el('login-error').textContent=e.message}}else if(ev.target.id==='mfa-verify-form'){ev.preventDefault();try{const r=await api('/api/mfa/verify','POST',{code:el('mfa-code').value});el('mfa-code').value='';await finishFullLogin(r)}catch(e){el('login-error').textContent=e.message}}else if(ev.target.id==='mfa-rotate-form'){ev.preventDefault();try{const r=await api('/api/mfa/recovery/rotate','POST',{code:el('rotate-code').value});el('rotate-code').value='';securityLoaded=false;showRecovery(r.recovery_codes)}catch(e){flash(e.message,true)}}else if(ev.target.id==='profile-form'){ev.preventDefault();await saveProfile(ev.target)}else if(ev.target.id==='cf-form'){ev.preventDefault();await submitCloudflare(ev.target,ev.submitter?.value||'preview')}});
async function submitCloudflare(form,action){
 const values=Object.fromEntries(new FormData(form));
 if(!values.token||!values.domain||!values.ipv4)return;
 const apply=action==='apply';
 if(apply && !confirm(`ساخت/تغییر ۱۰ رکورد DNS برای ${values.domain}؟ این عملیات واقعی Cloudflare است.`))return;
 const result=el('cf-result');result.textContent='در حال بررسی Cloudflare...';
 try{
   const data=await api('/api/workflow/cloudflare','POST',{
     token:values.token,domain:values.domain,ipv4:values.ipv4,dry_run:!apply,
     confirm:apply?'APPLY_CLOUDFLARE_DNS':''
   });
   result.textContent=(apply?'اعمال شد':'پیش‌نمایش')+'\n'+data.results.map(x=>`${x.action} ${x.type} ${x.name} -> ${x.content}`).join('\n')+ '\n'+data.note;
   if(apply){form.elements.token.value='';flash('رکوردهای Cloudflare بررسی/اعمال شدند؛ توکن از فرم پاک شد.');await update(true);}
 }catch(e){result.textContent='خطا: '+e.message;} 
}
// v0.6 guided operations: per-engine client config, build, install, and diagnostics.
let workflowLoaded=false;let danteLoaded=false;let setupLoaded=false;let workflowChoices=null;let selectedClientKind='';let workflowAltJob=null;
let workflowGuide=null;
let workflowOverview=null;
let workflowJobState={};
let workflowSlipPreflight=null;
let workflowDante=null;
let workflowDanteJob=null;
let workflowShared=null;
let workflowSoar=null;
let workflowTimer=null;
function wfBadge(value,good=false){return `<span class="badge ${good?'live':'bad'}">${esc(value)}</span>`;}
function wfRow(k,v){return `<div class="kv"><span class="label">${esc(k)}</span><b>${esc(v)}</b></div>`;}
async function loadWorkflow(){
  if(tab!=='workflow')return;
  const node=el('workflow');if(!node)return;
  let resolver=el('wf-resolver')?.value?.trim()||'1.1.1.1:53';
  let port=Number(el('wf-port')?.value||2080);
  if(!Number.isInteger(port)||port<1024||port>65535)port=2080;
  workflowLoaded=true;
  node.innerHTML='<div class="panel">در حال دریافت روش‌های کلاینت...</div>';
  try{
    const [guide,choice,build,alternate,soarStatus]=await Promise.all([
      api('/api/workflow/guide/'+selected+'?'+new URLSearchParams({resolver,port})),
      api('/api/workflow/client/options/'+selected),
      api('/api/workflow/jobs/build-client/'+selected).catch(()=>({state:'not-supported'})),
      ['dnstt','noizdns','vaydns'].includes(selected)?api('/api/workflow/jobs/build-alternate/'+selected).catch(()=>({state:'not-started'})):Promise.resolve({state:'not-supported'}),
      selected==='soar'?api('/api/workflow/soar/status').catch(()=>null):Promise.resolve(null)
    ]);
    if(tab!=='workflow')return;
    workflowGuide=guide;workflowChoices=choice;workflowJobState={build};workflowAltJob=alternate;workflowSoar=soarStatus;
    if(!choice.choices.some(x=>x.id===selectedClientKind))selectedClientKind=choice.default;
    drawWorkflow(resolver,port);
    if(workflowTimer)clearTimeout(workflowTimer);
    if(['running','queued'].includes(build.state)||['running','queued'].includes(alternate.state)){
      workflowTimer=setTimeout(()=>{if(tab==='workflow')loadWorkflow()},5000);
    }
  }catch(e){node.innerHTML=`<div class="notice danger-text">${esc(e.message)}</div><button class="btn" id="wf-refresh">تلاش مجدد</button>`;}
}
function drawWorkflow(resolver,port){
  const info=workflowGuide,choices=workflowChoices.choices;
  const engine=status.engines[selected];
  const choice=choices.find(x=>x.id===selectedClientKind)||choices[0];
  const alternate=choice.kind==='alternate';
  const buildState=alternate?workflowAltJob:workflowJobState.build;
  const settingsMatch=buildState.resolver===resolver && buildState.port===port;
  const buildReady=buildState.state==='succeeded' && settingsMatch;
  const canBuild=(alternate||info.can_build) && !['iodine','dns2tcp','xdns'].includes(selected);
  const download=alternate?`/api/workflow/client/alternate-download/${selected}`:`/api/workflow/client/download/${selected}`;
  const command=(selected==='noizdns'&&!alternate)
    ? `DUC_DNS_RESOLVER=${resolver} DUC_CLIENT_PORT=${port} ./run-noizdns.sh`
    :alternate&&choice.id==='slipnet'?`DUC_DNS_RESOLVER=${resolver} DUC_CLIENT_PORT=${port} ./run-client.sh`
    :alternate&&choice.id==='dnstt'?`DUC_DNS_RESOLVER=${resolver} DUC_CLIENT_PORT=${port} ./run-client.sh`
    :info.example_command||'نیازمند راهنمای خاص این موتور';
  const isSocks=['dnstt','noizdns','vaydns','soar','slipstream'].includes(selected);
  const probe=isSocks?`curl --socks5-hostname 127.0.0.1:${port} --proxy-user USER:PASS https://api.ipify.org`:(info.verification_command||'به راهنمای موتور مراجعه کنید');
  el('workflow').innerHTML=`
    <div class="panel spaced"><h2>انتخاب موتور و کلاینت</h2>
      <p class="muted-block">موتور، برنامهٔ روی VPS است؛ کلاینت، برنامهٔ روی Debian یا Windows است. انتخاب کلاینت موتور فعال را تغییر نمی‌دهد.</p>
      <div class="form-grid">
        <label class="field">موتور سرور<select id="workflow-engine">${engines.map(e=>`<option value="${e}" ${selected===e?'selected':''}>${esc(names[e])}</option>`).join('')}</select></label>
        <label class="field">Resolver کلاینت (IP:port)<input id="wf-resolver" dir="ltr" value="${esc(resolver)}"></label>
        <label class="field">پورت محلی TCP<input id="wf-port" dir="ltr" type="number" min="1024" max="65535" value="${port}"></label>
      </div>
      <div class="engine-actions"><button class="btn small" id="wf-refresh">اعمال Resolver / بازخوانی</button><button class="btn small" data-go="engines">کنترل موتورها</button><button class="btn small" data-go="dante">تنظیمات Dante</button></div>
      <div class="notice spaced" style="margin-top:16px">دامنه: <code>${esc(info.domain)}</code> · Backend پیش‌فرض: <code>127.0.0.1:1080</code> · فقط یک کلاینت می‌تواند روی <code>127.0.0.1:${port}</code> گوش دهد.</div>
      <h3>کدام کلاینت را می‌خواهی؟</h3>
      <div class="workflow-choice-grid">${choices.map(x=>`<label class="client-choice"><input type="radio" name="client-choice" value="${esc(x.id)}" ${x.id===choice.id?'checked':''}><span><strong>${esc(x.label)}</strong><small>${esc(x.note)}</small><small>${x.tested?'✓ آزموده‌شده در سطح ذکرشده':'⚠ سازگاری با این سرور هنوز تست نشده'}</small></span></label>`).join('')}</div>
    </div>
    <div class="stepbar"><div><strong>۱ · موتور</strong>${esc(names[selected])}</div><div><strong>۲ · کلاینت</strong>${esc(choice.label)}</div><div><strong>۳ · Resolver</strong><code>${esc(resolver)}</code></div><div><strong>۴ · تست</strong>SOCKS5 + HTTPS</div></div>
    <div class="grid columns">
      <div class="panel"><h2>ساخت و دریافت ${esc(choice.label)}</h2>
        ${wfRow('وضعیت ساخت',buildState.state||'not-started')}
        ${buildState.message?`<p class="dim">${esc(buildState.message)}</p>`:''}
        ${buildState.state==='succeeded'&&!settingsMatch?'<div class="notice">این ZIP با Resolver/پورت دیگری ساخته شده است. برای اعمال مقادیر انتخابی، بسته را دوباره بساز.</div>':''}
        ${buildState.resolver?`<p class="dim">تنظیمات آخرین بسته: ${esc(buildState.resolver)} · ${esc(buildState.port)}</p>`:''}
        ${!choice.tested?'<div class="notice">این ترکیب در محیط شما هنوز تست انتهابه‌انتها نشده است. وضعیت «آمادهٔ دانلود» معادل «اتصال موفق» نیست.</div>':''}
        ${selected==='soar'&&!workflowSoar?.preflight?.ready?`<div class="notice danger-text">Soar Server هنوز آماده نیست: ${esc((workflowSoar?.preflight?.issues||[]).join('، ')||'وضعیت نامشخص')}</div>`:''}
        <div class="engine-actions">${canBuild?(selected==='soar'?`<button class="btn primary" id="soar-build" ${['queued','running'].includes(buildState.state)?'disabled':''}>ساخت کلاینت Soar</button>`:`<button class="btn primary" id="wf-build" ${['queued','running'].includes(buildState.state)?'disabled':''}>ساخت ${alternate?'کلاینت جایگزین':'کلاینت اصلی'}</button>`):'<span class="dim">برای این کلاینت فقط راهنمای نصب موجود است.</span>'}
        ${buildReady?`<a class="btn primary" href="${download}" download>دانلود ZIP ${esc(choice.label)}</a>`:''}</div>
        ${buildState.sha256?`<pre class="log mono">SHA-256: ${esc(buildState.sha256)}</pre>`:''}
        <h3>دستور اجرا</h3><pre id="wf-command" class="log mono" dir="ltr">${esc(command)}</pre>
        <button class="btn small" id="wf-copy">کپی دستور</button>
        <a class="btn small" href="/api/workflow/client/guide-zip/${selected}?${new URLSearchParams({resolver,port})}" download>راهنمای عمومی (بدون باینری)</a>
        <p class="dim">بستهٔ اصلی و جایگزین دو Job و دو فایل مستقل دارند. کلید خصوصی سرور و رمز Dante داخل ZIP نیست. ${selected==='master'?'هشدار: MasterDnsVPN شامل کلید اشتراکی محرمانه خودش است.':''}</p>
        ${selected==='slipstream'?renderSlipstreamClientHelp(engine.config):''}
      </div>
      <div class="panel"><h2>تست بعد از اجرا</h2>
        <p class="muted-block">کلاینت قبلی را Stop کن؛ سپس فقط کلاینت انتخاب‌شده را اجرا کن. برای SlipNet با <code>--dns</code> از Resolver عمومی استفاده می‌شود.</p>
        <pre class="log mono" dir="ltr">ss -ltnp '( sport = :${port} )'
${esc(probe)}</pre>
        <div class="notice">در تست NoizDNS/SlipNet با Resolver عمومی، اعتبارنامهٔ صحیح پذیرفته شد و رمز اشتباه/بدون رمز رد شد. این نتیجه الزاماً برای سایر موتورهای پشتیبانی‌شدهٔ SlipNet معتبر نیست.</div>
        <div class="engine-actions"><button class="btn" data-go="monitor">مانیتورینگ</button><button class="btn" data-go="dns">بررسی DNS</button></div>
        <a href="${esc(info.docs)}" target="_blank" rel="noopener noreferrer">مستندات موتور</a>
      </div>
    </div>`;
}
async function loadDante(){
  if(tab!=='dante')return;
  danteLoaded=true;el('dante').innerHTML='<div class="panel">دریافت وضعیت Dante...</div>';
  try{
    const [dante,shared,job]=await Promise.all([
      api('/api/workflow/dante/status'),api('/api/workflow/shared-socks/status'),
      api('/api/workflow/jobs/setup-dante/dante').catch(()=>({state:'not-started'}))]);
    if(tab!=='dante')return;
    workflowDante=dante;workflowShared=shared;workflowDanteJob=job;
    const selectedModes=['slipstream','dnstt','vaydns','noizdns'];
    const info=shared?.backend||{};
    el('dante').innerHTML=`
      <div class="panel spaced"><h2>Shared Dante — سرویس مستقل SOCKS5</h2>
        <div class="notice">Dante روی VPS فقط به <code>127.0.0.1:1080</code> متصل است و احراز هویت دارد. این سرویس جزو موتورهای Exclusive Mode نیست؛ کنترل آن را با Start/Stop موتور DNS اشتباه نگیر.</div>
        <div class="diagnostic-grid">${[['آمادگی Dante',info.ready?'آماده':'نیازمند بررسی'],['پورت',info.bind||'127.0.0.1:1080'],['موتور فعال',(shared?.active_dns||[]).join(', ')||'none'],['Exclusive Mode',shared?.exclusive_healthy?'سالم':'تداخل'],['Job نصب',job.state==='not-started'?'ثبت نشده (وضعیت سرویس مستقل است)':job.state||'—']].map(([k,v])=>`<div><span class="label">${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')}</div>
        <div class="engine-actions"><button class="btn primary" id="wf-shared-install">نصب / بررسی Dante</button><button class="btn" id="dante-refresh">بازخوانی وضعیت</button></div>
        <p class="dim">رمز Dante در پنل نمایش داده یا همراه بستهٔ کلاینت ارسال نمی‌شود. تغییر رمز سرویس موجود بدون روند گردش امن اعتبارنامه انجام نمی‌شود.</p>
      </div>
      <div class="panel spaced"><h2>اتصال موتورهای TCP به Dante</h2>
        <p class="muted-block">این عملیات فقط مقصد Backend موتورهای سازگار را تغییر می‌دهد. اگر موتور فعال باشد، ممکن است Restart و قطع موقت ارتباط رخ دهد.</p>
        <div id="shared-modes" class="form-grid">${selectedModes.map(id=>`<label class="field"><span><input style="width:auto" type="checkbox" value="${id}" ${shared?.engines?.[id]?.mode==='shared-dante'?'checked':''}> ${esc(names[id])} · ${esc(shared?.engines?.[id]?.mode||'unknown')}</span></label>`).join('')}</div>
        <div class="engine-actions"><button class="btn primary" id="wf-shared-attach" ${info.ready?'':'disabled'}>اتصال به Dante</button><button class="btn subtle" id="wf-shared-restore">بازگردانی مقصدهای پیشین</button></div>
        <h3>مقصد Loopback سفارشی</h3>
        <label class="field" style="max-width:300px">TCP Backend<input id="shared-custom-target" dir="ltr" value="127.0.0.1:1090"></label>
        <button class="btn small" id="wf-shared-custom">تنظیم فقط برای یک موتور</button>
        <p class="dim">این مقصد باید از قبل وجود داشته باشد. عملیات هیچ سرویس یا پورت عمومی جدیدی ایجاد نمی‌کند.</p>
      </div>`;
  }catch(e){el('dante').innerHTML=`<div class="notice danger-text">${esc(e.message)}</div>`;}
}
async function loadSetup(){
  if(tab!=='setup')return;
  setupLoaded=true;el('setup').innerHTML='<div class="panel">در حال بررسی نصب و سلامت...</div>';
  try{
    const [overview,job]=await Promise.all([api('/api/workflow/overview'),api('/api/workflow/jobs/install-server/'+selected).catch(()=>({state:'not-supported'}))]);
    if(tab!=='setup')return;
    workflowOverview=overview;workflowJobState.inst=job;
    const h=overview.health||{},svc=h.services||{},r=h.resources||{};
    const rows=Object.entries(overview.provision?.engines||{}).map(([id,x])=>`<div class="kv"><span class="label">${esc(names[id]||id)}</span><strong>${esc(x.state||'unknown')}</strong></div>`).join('');
    el('setup').innerHTML=`<div class="grid columns"><div class="panel"><h2>نصب و آماده‌سازی موتورهای سرور</h2>
      <p class="muted-block">نصب باینری مستقل از فعال‌سازی است؛ موتور فعال بدون درخواست روشن/خاموش نمی‌شود.</p>
      ${rows||'<p class="dim">گزارش نصب گروهی ثبت نشده است.</p>'}
      <p class="dim">برای نصب قابل ادامهٔ همهٔ موتورهای تأییدشده، در VPS دستور <code>bash upgrade.sh --install-missing</code> را اجرا کن.</p>
      <label class="field">موتور سرور<select id="setup-engine">${engines.map(e=>`<option value="${e}" ${selected===e?'selected':''}>${esc(names[e])}</option>`).join('')}</select></label>
      <div class="engine-actions">${overview.capabilities[selected]?.installable?'<button class="btn primary" id="wf-install">نصب / به‌روزرسانی موتور انتخابی</button>':'<span class="dim">این موتور در نصب خودکار یا نصب دستی جداگانه آماده می‌شود.</span>'}<button class="btn" data-go="engines">کنترل موتور فعال</button></div>
      ${wfRow('Job اخیر',job.state||'—')}
    </div><div class="panel"><h2>سلامت زیرساخت</h2>
      <div class="diagnostic-grid">${[['پنل وب',svc.web],['Agent',svc.agent],['Caddy',svc.caddy],['MFA',h.mfa_file_configured],['پورت 53',(h.port53||[]).join(', ')||'آزاد'],['RAM آزاد',Math.round((r.ram_available||0)/1048576)+' MiB'],['Swap',Math.round((r.swap_total||0)/1048576)+' MiB'],['دیسک آزاد',Math.round((r.disk_free||0)/1048576)+' MiB']].map(([k,v])=>`<div><span class="label">${esc(k)}</span><strong>${esc(typeof v==='boolean'?(v?'فعال':'غیرفعال'):v)}</strong></div>`).join('')}</div>
      <p class="dim">سلامت سیستم و موفقیت تونل واقعی دو بررسی مستقل هستند. تست‌های DNS و SOCKS5 را از کلاینت اجرا کن.</p><div class="engine-actions"><button class="btn" data-go="monitor">مانیتورینگ</button><button class="btn" data-go="dns">DNS</button></div>
    </div></div>`;
  }catch(e){el('setup').innerHTML=`<div class="notice danger-text">${esc(e.message)}</div>`;}
}
async function sharedBackendWeb(mode){
 const checked=[...document.querySelectorAll('#shared-modes input[type=checkbox]:checked')].map(x=>x.value);
 if(!checked.length){flash('حداقل یک موتور TCP انتخاب کن',true);return;}
 const title=mode==='dante'?'اتصال موتورهای انتخاب‌شده به Shared Dante':'بازگردانی مقصد TCP قبلی';
 
 if(!confirm(title+'؟\n'+checked.join(', ')+'\nدر صورت فعال‌بودن موتور انتخاب‌شده، Restart و قطع موقت اتصالات رخ می‌دهد.\nUDP/53 همچنان فقط در کنترل Exclusive Mode است.'))return;
 busy=true;
 try{
   const r=await api('/api/workflow/shared-socks/activate','POST',{
     mode,engines:checked,confirm:'shared-socks:'+mode
   });
   flash(title+' · '+r.stage+' · changed: '+(r.changed||[]).join(','));
   await update(true);await loadDante();
 }catch(e){flash(e.message,true)}finally{busy=false;}
}
async function installDanteWeb(){
 if(!confirm('Dante را فقط روی 127.0.0.1:1080 نصب کنیم؟\nدر نصب اول رمز تولید می‌شود؛ در نصب مجدد رمز موجود حفظ می‌شود.\nپورت 53 و موتور فعلی تغییر نمی‌کنند.'))return;
 try{const r=await api('/api/workflow/jobs/setup-dante/dante','POST',{confirm:'setup-dante:dante'});flash('نصب Dante: '+r.state);await loadDante();}
 catch(e){flash(e.message,true)}
}
async function activateDanteWeb(mode){
 const msg=mode==='socks5'?'تغییر Backend از SSH به SOCKS5 Dante':'بازگشت Backend به SSH';
 if(!confirm(msg+'؟\nاگر SlipStream فعال باشد، سرویس آن Restart می‌شود و اتصال‌های جاری قطع خواهند شد.'))return;
 busy=true;
 try{const r=await api('/api/workflow/dante/activate','POST',{mode,confirm:'activate:'+mode});flash(msg+' · '+r.stage);await update(true);await loadDante();}
 catch(e){flash(e.message,true)}finally{busy=false}
}
async function startWfJob(action){
 const title=action==='install-server'?'نصب باینری/پکیج سرور':'ساخت بسته کلاینت';
 const question=action==='install-server'&&selected==='slipstream'
  ?`نصب/اعتبارسنجی SlipStream از AliRezaBeigy؟\nRelease: 42e3e75\nبدون کامپایل Rust؛ بدون تغییر سرویس فعال، UDP/53، Caddy یا NAT.\nموتور فقط پس از سوئیچ جداگانه روشن می‌شود.`
  :`${title} برای ${names[selected]}؟\nاین کار سورس بالادستی را دریافت/کامپایل می‌کند و ممکن است RAM/CPU مصرف کند. عملیات موتور فعال را بدون تأیید متوقف نمی‌کند.`;
 if(!confirm(question))return;
 const params=action==='build-client'||action==='build-alternate'?{resolver:el('wf-resolver')?.value?.trim()||'1.1.1.1:53',port:Number(el('wf-port')?.value||2080)}:{};
 try{const result=await api('/api/workflow/jobs/'+action+'/'+selected,'POST',{confirm:action+':'+selected,...params});flash(title+' شروع شد: '+result.state);if(tab==='setup')await loadSetup();else await loadWorkflow();}
 catch(e){flash(e.message,true);}
}

boot();


async function customBackendWeb(){
 const checked=[...document.querySelectorAll('#shared-modes input[type=checkbox]:checked')].map(x=>x.value);
 if(checked.length!==1){flash('برای پورت سفارشی فقط یک موتور انتخاب کن',true);return}
 const target=el('shared-custom-target')?.value?.trim()||'';
 if(!/^127\.0\.0\.1:[0-9]{1,5}$/.test(target)){flash('مقصد سفارشی فقط 127.0.0.1:PORT است',true);return}
 if(!confirm(`مقصد ${checked[0]} به ${target} تغییر کند؟ سرویس مقصد باید از قبل آماده باشد. موتور فعال Restart خواهد شد.`))return;
 busy=true;
 try{const r=await api('/api/workflow/shared-socks/activate','POST',{mode:'custom',engines:checked,target,confirm:'shared-socks:custom'});flash('مقصد تغییر کرد: '+r.stage);await update(true);await loadDante()}
 catch(e){flash(e.message,true)}finally{busy=false}
}
async function loadClientTelemetry(){
 try{telemetryData=await api('/api/workflow/telemetry');if(tab==='monitor')renderMonitor()}
 catch(e){if(tab==='monitor')flash('خطا در گزارش‌های کلاینت: '+e.message,true)}
}
async function importClientReport(){
 const text=el('client-report-json')?.value?.trim();if(!text){flash('گزارش JSON خالی است',true);return}
 try{const report=JSON.parse(text);if(!confirm('این گزارش از کلاینت خودت است و شامل هیچ رمز عبوری نیست؟'))return;
 await api('/api/workflow/telemetry','POST',{report});flash('گزارش کلاینت ثبت شد');await loadClientTelemetry()}
 catch(e){flash('گزارش معتبر نیست: '+e.message,true)}
}


// v0.9.8: same read-only readiness contract used by the local TUI.
// Do not confuse systemd/ZIP status with an end-to-end client field test.
let readinessSnapshot=null,readinessFetched=0,readinessInFlight=false;
function renderReadiness(){
  const root=el('overview');if(!root)return;
  const data=readinessSnapshot;
  const chosen=data?.active?.[0]||selected;
  const info=data?.engines?.[chosen];
  const d=data?.dante;
  const variants=(info?.clients||[]).map(c=>`<div class="kv"><span class="label">${esc(c.id)} · ${esc(c.kind)}</span><strong>${esc(c.build_state)}</strong></div>`).join('');
  const panel=`<div id="readiness-summary" class="panel spaced" style="margin-top:16px">
    <h2>خلاصهٔ آمادگی عملیاتی · Web / TUI</h2>
    ${data?.instance?`<p class="dim">Instance: <code>${esc(data.instance.domain)}</code> · IP: <code>${esc(data.instance.public_ipv4)}</code></p>`:'<p class="dim">Instance: نصب قدیمی، بدون هویت ثبت‌شده</p>'}
    <div class="notice">این اطلاعات فقط وضعیت محلی Agent است؛ اتصال اینترنت، پایداری DNS و مقاومت در برابر DPI را تأیید نمی‌کند.</div>
    ${data ? `<div class="diagnostic-grid">${[
      ['Exclusive Mode',data.exclusive_healthy?'سالم':'تداخل موتور'],
      ['موتور فعال',data.active.join(', ')||'هیچ‌کدام'],
      ['آمادگی سرور',info?.server_ready?'آماده':'نیازمند بررسی'],
      ['Dante',d?.ready?'آماده و اعتبارسنجی‌شده':'نیازمند بررسی']
    ].map(([k,v])=>`<div><span class="label">${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')}</div>
    <h3>بسته‌های کلاینت ${esc(chosen)}</h3>${variants||'<p class="dim">کلاینتی برای این موتور تعریف نشده است.</p>'}
    <p class="dim">وضعیت ساخت فقط مربوط به Job تولید ZIP است، نه آزمایش انتهابه‌انتها.</p>`
    : '<p class="dim">در حال دریافت گزارش یکپارچهٔ سلامت...</p>'}
    <p class="dim">TUI محلی VPS: <code>sudo bash /opt/dns-unified-control/scripts/duc-tui.sh</code></p>
  </div>`;
  root.insertAdjacentHTML('beforeend',panel);
}
async function refreshReadinessIfNeeded(){
  if(readinessInFlight||Date.now()-readinessFetched<30000)return;
  readinessInFlight=true;
  try{
    const r=await api('/api/workflow/readiness');
    readinessSnapshot=r;
    if(tab==='overview'&&status){
      const old=el('readiness-summary');if(old)old.remove();
      renderReadiness();
    }
  }catch(e){
    if(tab==='overview'&&status&&!readinessSnapshot){
      const n=el('readiness-summary');if(n)n.textContent='گزارش عملیاتی قابل دریافت نیست: '+e.message;
    }
  }finally{readinessFetched=Date.now();readinessInFlight=false;}
}
