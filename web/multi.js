/* DUC Multi Engine panel integration. Uses existing authenticated `api()` + CSRF. */
'use strict';
(function(){
const ORDER=['master','soar','cotten','slipstream','noizdns','dnstt','vaydns'];
const NAMES={master:'MasterDnsVPN',soar:'Soar',cotten:'CottenDNS',slipstream:'SlipStream',noizdns:'NoizDNS',dnstt:'DNSTT',vaydns:'VayDNS'};
const $=id=>document.getElementById(id);
const escapeHTML=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let lastPlan=null;
const container=document.createElement('section');container.id='ducmulti-panel';container.hidden=true;
container.setAttribute('role','dialog');container.setAttribute('aria-label','Multi Engine Mode');
container.innerHTML=`<div class="ducm-bar"><h2 style="flex:1">مدیریت Exclusive / Multi-Engine</h2><button id="ducm-close" type="button">بستن</button></div>
<p>پیش‌بررسی الزامی است؛ تغییر حالت می‌تواند تونل‌های متصل را قطع کند. اجرای هم‌زمان فقط برای موتورهایی مجاز است که آداپتور و صحت سرویس آن‌ها تأیید شده باشد.</p>
<div class="ducm-bar"><label><input type="radio" name="ducm-mode" value="exclusive"> Exclusive</label><label><input type="radio" name="ducm-mode" value="multi" checked> Multi-Engine</label></div>
<div id="ducm-engines" class="ducm-grid"></div>
<div class="ducm-bar"><label>Bind IPv4 داخلی سرور (AWS NAT: آدرس ens5) <input type="text" id="ducm-ip" placeholder="Auto detect" maxlength="45"></label></div>
<div class="ducm-bar"><button id="ducm-preview" type="button">بررسی و پیش‌نمایش</button><button id="ducm-apply" type="button" disabled>اعمال با yes/no</button><button id="ducm-refresh" type="button">وضعیت فعلی</button></div><pre id="ducm-status">ابتدا وضعیت را دریافت کن...</pre>`;
document.body.appendChild(container);
$('ducm-engines').innerHTML=ORDER.map(e=>`<label><input class="ducm-choice" type="checkbox" value="${e}" checked><span>${escapeHTML(NAMES[e])}</span></label>`).join('');
function selected(){return [...container.querySelectorAll('.ducm-choice:checked')].map(e=>e.value)}
function mode(){return container.querySelector('input[name=ducm-mode]:checked')?.value||'exclusive'}
function payload(){return {mode:mode(),engines:selected(),listen_ip:$('ducm-ip').value.trim()||null}}
function show(v){$('ducm-status').textContent=typeof v==='string'?v:JSON.stringify(v,null,2)}
async function getStatus(){try{const r=await api('/api/multi/status');show(r)}catch(e){show(e.message)}}
async function preview(){try{lastPlan=null;$('ducm-apply').disabled=true;const r=await api('/api/multi/plan','POST',payload());lastPlan=r;show(r);$('ducm-apply').disabled=!r.ready}catch(e){show(e.message)}}
async function apply(){
  if(!lastPlan?.ready)return;
  const body=payload();
  if(JSON.stringify(body.engines)!==JSON.stringify(lastPlan.selected)||body.mode!==lastPlan.mode||(body.listen_ip&&body.listen_ip!==lastPlan.listen_ip)){
    show('تنظیمات تغییر کرده‌اند؛ دوباره پیش‌بررسی را اجرا کن.');$('ducm-apply').disabled=true;return;
  }
  if(!window.confirm('آیا اجرای تغییر حالت DNS را تأیید می‌کنی؟ yes / no\nممکن است اتصال کلاینت‌های فعلی قطع شود.'))return;
  $('ducm-apply').disabled=true;
  try{const r=await api('/api/multi/apply','POST',{...body,confirm:'yes'});show(r)}catch(e){show(e.message)}
}
function open(){container.hidden=false;getStatus()}
function close(){container.hidden=true}
document.addEventListener('click',ev=>{
  if(ev.target.closest('#ducmulti-nav')){ev.preventDefault();open()}
  if(ev.target.closest('#ducm-close'))close();
  if(ev.target.closest('#ducm-preview'))preview();
  if(ev.target.closest('#ducm-refresh'))getStatus();
  if(ev.target.closest('#ducm-apply'))apply();
});
container.addEventListener('change',e=>{if(e.target.matches('input')){lastPlan=null;$('ducm-apply').disabled=true;
  if(e.target.name==='ducm-mode'&&e.target.value==='exclusive'){
    const items=container.querySelectorAll('.ducm-choice:checked');items.forEach((x,i)=>{if(i>0)x.checked=false});
  }
}});
container.addEventListener('input',e=>{if(e.target.id==='ducm-ip'){$('ducm-apply').disabled=true;lastPlan=null}});
})();
