'use strict';
const formatSize = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KiB` : `${(n/1048576).toFixed(2)} MiB`;
const count = n => Number(n || 0).toLocaleString('tr-TR');
const statusLabel = s => ({queued:'Kuyrukta',running:'İnceleniyor',completed:'Tamamlandı',cancelled:'İptal edildi',error:'Hata'})[s] || s;
const tableDefs = {
  strings: [['offset','Ofset'],['encoding','Kodlama'],['text','Dizgi']],
  symbols: [['address','Adres'],['name','Sembol / Fonksiyon'],['type','Tür'],['direction','Yön'],['size','Boyut']],
  sections: [['address','Adres'],['name','Bölüm'],['type','Tür'],['offset','Dosya ofseti'],['size','Boyut'],['permissions','Bayraklar']],
  disassembly: [['address','Adres'],['bytes','Baytlar'],['mnemonic','Komut'],['operands','Operandlar'],['function','Fonksiyon'],['section','Bölüm']],
  indicators: [['offset','Ofset'],['kind','Tür'],['evidence','Kanıt']]
};
const filterDefs = {
  strings: [['utf-8','ASCII / UTF-8'],['utf-16-le','UTF-16 LE'],['utf-16-be','UTF-16 BE']],
  symbols: [['import','İçe aktarılanlar'],['defined/export candidate','Tanımlı semboller'],['STT_FUNC','Fonksiyonlar']],
  indicators: [['url','URL'],['domain','Alan adı'],['ip','IP adresi'],['path','Dosya yolu'],['error','Hata metni']]
};
function buildRows(table, rows) {
  return rows.map(row => table.map(([key]) => {
    const value = row[key] ?? '—';
    return key === 'offset' ? `0x${Number(value).toString(16)}` : String(value);
  }));
}
if (typeof module !== 'undefined') module.exports = {formatSize,count,statusLabel,buildRows,tableDefs};

if (typeof document !== 'undefined') {
const $ = id => document.getElementById(id);
const state = {mode:'static',file:null,job:null,summary:null,tab:'overview',offset:0,total:0,rows:[],history:[],page:'workspace',busy:false,tool:null,mcp:null,pending:null,viewRequest:0,rendered:null,uploading:false};
const hashToken = new URLSearchParams(location.hash.slice(1)).get('token');
if (hashToken) { sessionStorage.setItem('rewb-token',hashToken); history.replaceState(null,'',location.pathname); }
const token = sessionStorage.getItem('rewb-token') || '';
let toastTimer, searchTimer, polling = false;
function E(tag, cls, text) { const node=document.createElement(tag); if(cls) node.className=cls; if(text!==undefined) node.textContent=String(text); return node; }
function icon(name) { const svg=document.createElementNS('http://www.w3.org/2000/svg','svg'); const use=document.createElementNS(svg.namespaceURI,'use'); use.setAttribute('href',`#i-${name}`); svg.append(use); svg.setAttribute('aria-hidden','true'); return svg; }
function show(id,yes=true) { $(id).classList.toggle('hidden',!yes); }
function error(message) { $('error-text').textContent=message; show('error-banner'); }
function toast(message) { $('toast').textContent=message; show('toast'); clearTimeout(toastTimer); toastTimer=setTimeout(()=>show('toast',false),3500); }
async function api(path,options={}) {
  const headers = {'Authorization':`Bearer ${token}`,...options.headers};
  const response = await fetch(path,{...options,headers,cache:'no-store'});
  if(!response.ok) {
    let message='Sunucuya ulaşılamadı.';
    try { message=(await response.json()).error || message; } catch (_) {}
    if(response.status===401) show('session-warning');
    throw new Error(message);
  }
  return options.blob ? response.blob() : response.json();
}
const post = (path,data={}) => api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
function safe(fn) { return (...args)=>Promise.resolve().then(()=>fn(...args)).catch(e=>error(e.message || 'İşlem tamamlanamadı.')); }
async function copy(text) { if(!navigator.clipboard) throw new Error('Pano kullanılamıyor. Metni seçerek kopyalayabilirsin.'); await navigator.clipboard.writeText(text); toast('Panoya kopyalandı.'); }
function page(name) {
  state.page=name;
  document.querySelectorAll('.page').forEach(el=>el.classList.toggle('hidden',el.id!==`page-${name}`));
  document.querySelectorAll('[data-page]').forEach(el=>el.classList.toggle('active',el.dataset.page===name));
  $('breadcrumb').textContent=({workspace:'Yeni analiz',history:'Analiz geçmişi',dynamic:'Dinamik analiz',mcp:'MCP araçları',settings:'Çalışma ortamı'})[name];
  if(name==='history') renderHistory();
  if(name==='mcp') refreshMCP().catch(e=>error(e.message));
  if(name==='dynamic') {
    $('dynamic-file').textContent=state.summary ? `Seçili analiz: ${state.summary.file.name} · ${state.summary.file.hashes.sha256.slice(0,16)}…` : 'Çalışma alanından bir dosyanın statik analizini tamamla.';
    $('dynamic-prepare').disabled=!state.summary || state.busy;
    refreshDynamic().catch(e=>error(e.message));
  }
  window.scrollTo({top:0,behavior:'instant'});
}
function setMode(mode) {
  if(state.busy || state.uploading) return;
  state.mode=mode;
  document.querySelectorAll('[data-mode]').forEach(el=>{const selected=el.dataset.mode===mode;el.classList.toggle('selected',selected);el.setAttribute('aria-pressed',selected);});
  $('analyze').firstChild.textContent=mode==='reverse' ? 'Tersine mühendisliği başlat ' : 'Analizi başlat ';
}
function choose(file) {
  if(state.busy || state.uploading) return;
  if(file && file.size>67108864) { error('Dosya boyutu en fazla 64 MiB olabilir.'); return; }
  state.file=file;
  show('selected-file',!!file); show('dropzone',!file);
  $('analyze').disabled=!file;
  if(file) { $('selected-name').textContent=file.name; $('selected-size').textContent=`${formatSize(file.size)} · Yerel incelemeye hazır`; }
}
async function start() {
  if(!state.file || state.busy || state.uploading) return;
  show('error-banner',false); state.uploading=true; $('analyze').disabled=true;
  $('analyze').firstChild.textContent='Dosya aktarılıyor… ';
  try {
    const data=await api(`/api/analyze?mode=${state.mode}`,{method:'POST',headers:{'Content-Type':'application/octet-stream','X-File-Name':encodeURIComponent(state.file.name)},body:state.file});
    state.job=data.id;state.busy=true;state.summary=null;state.rendered=null;
    show('results',false);show('progress-panel');$('progress-title').textContent=state.file.name;
    $('progress-message').textContent='İnceleme başlıyor';$('progress-bar').value=0;$('progress-percent').textContent='0%';
    $('progress-panel').scrollIntoView({behavior:'smooth',block:'nearest'});
    await pollJob();
  } finally { state.uploading=false; $('analyze').disabled=state.busy || !state.file; $('analyze').firstChild.textContent=state.mode==='reverse'?'Tersine mühendisliği başlat ':'Analizi başlat '; }
}
async function pollJob() {
  if(!state.job) return;
  const item=await api(`/api/jobs/${state.job}`);
  state.busy=['queued','running'].includes(item.state);
  $('analyze').disabled=state.busy || state.uploading || !state.file;
  $('file-input').disabled=state.busy; $('remove-file').disabled=state.busy;
  $('progress-title').textContent=`${item.name} · ${statusLabel(item.state)}`;
  $('progress-message').textContent=item.message;
  $('progress-bar').value=item.progress;$('progress-percent').textContent=`${item.progress}%`;
  show('progress-panel',state.busy); $('cancel-analysis').disabled=!state.busy;
  if(item.state==='completed' && state.rendered!==item.id) {
    state.summary=item.summary;state.rendered=item.id;state.tab='overview';state.offset=0;
    renderResult();await refreshHistory();
  } else if(['error','cancelled'].includes(item.state) && state.rendered!==item.id) {
    state.rendered=item.id; toast(item.message);await refreshHistory();
  }
}
function renderResult() {
  const s=state.summary;if(!s)return;
  show('results'); $('result-name').textContent=s.file.name;
  $('result-subtitle').textContent=`${formatSize(s.file.size)}  /  ${s.format}  /  ${s.architecture}`;
  const stats=$('result-stats');stats.replaceChildren();
  [['DOSYA TÜRÜ',s.format,s.bits==='—'?'İmzadan tanımlandı':`${s.bits} · ${s.architecture}`],['DİZGİLER',count(s.counts.strings),'ASCII / UTF-8 / UTF-16'],['SEMBOLLER',count(s.counts.symbols),'Fonksiyonlar ve içe aktarımlar'],['ENTROPİ',s.metrics.entropy!==undefined?`${s.metrics.entropy.toFixed(2)} / 8`:'—','Veri yoğunluğu · zararlılık hükmü değil']].forEach(([label,value,sub])=>{
    const card=E('div','stat');card.append(E('span','stat-label',label),E('span','stat-value',value),E('span','stat-sub',sub));stats.append(card);
  });
  tab('overview');
}
function detailList(values) {
  const list=E('dl','detail-list');
  values.forEach(([label,value])=>{const row=E('div','detail-row');row.append(E('dt','',label),E('dd','',value));list.append(row);});return list;
}
function detailHeading(text,name) {const h=E('h3','detail-heading',text);if(name)h.prepend(icon(name));return h;}
function overview() {
  const s=state.summary,container=$('overview-view');container.replaceChildren();
  const grid=E('div','overview-grid'),left=E('div','overview-column'),right=E('div','overview-column');
  left.append(detailHeading('Dosya kimliği','file'),detailList([['Dosya boyutu',formatSize(s.file.size)],['Mimari',s.architecture],['Bit genişliği',s.bits],['ABI',s.abi],['Giriş noktası',s.entry],['Analiz tarihi',s.created_at ? new Date(s.created_at).toLocaleString('tr-TR'):'—']]));
  left.append(detailHeading('Hash değerleri','shield'));
  Object.entries(s.file.hashes).forEach(([name,value])=>{const row=E('div','hash-item'),body=E('div');body.append(E('small','',name.toUpperCase()),E('code','',value));const button=E('button','icon-button');button.setAttribute('aria-label',`${name} değerini kopyala`);button.append(icon('copy'));button.addEventListener('click',safe(()=>copy(value)));row.append(body,button);left.append(row);});
  const entropy=E('div','entropy-card'),heading=E('h3','','Entropi dağılımı');heading.append(E('span','',s.metrics.entropy===undefined?'—':s.metrics.entropy.toFixed(2)));entropy.append(heading);
  if(s.metrics.blocks?.length) {
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 400 90');svg.setAttribute('preserveAspectRatio','none');svg.classList.add('entropy-chart');svg.setAttribute('role','img');svg.setAttribute('aria-label','Dosya boyunca 0 ile 8 arasında entropi dağılımı');
    const blocks=s.metrics.blocks,points=blocks.length===1?`0,${85-blocks[0].entropy*10} 400,${85-blocks[0].entropy*10}`:blocks.map((b,i)=>`${i/(blocks.length-1)*400},${85-b.entropy*10}`).join(' ');
    const area=document.createElementNS(svg.namespaceURI,'polygon');area.setAttribute('points',`0,90 ${points} 400,90`);area.setAttribute('class','chart-area');
    const line=document.createElementNS(svg.namespaceURI,'polyline');line.setAttribute('points',points);line.setAttribute('class','chart-line');svg.append(area,line);entropy.append(svg);
    const labels=E('div','chart-labels');labels.append(E('span','','0x0'),E('span','',`0x${s.file.size.toString(16)}`));entropy.append(labels);
  }
  entropy.append(E('p','',s.metrics.note || 'Entropi ölçümü bu analizde bulunmuyor.'));right.append(entropy,detailHeading('Kütüphane bağımlılıkları','code'));
  const dependencies=E('div','dependency-chips');s.dependencies.forEach(value=>dependencies.append(E('span','',value)));if(!s.dependencies.length)dependencies.append(E('p','muted small','Bağımlılık kaydı bulunmadı veya format desteklenmiyor.'));right.append(dependencies);
  Object.entries(s.modules).forEach(([name,module])=>{
    const note=E('div',module.status==='ok'?'notice good':'notice');note.append(E('strong','',`${name} · ${module.status==='ok'?'Hazır':module.status==='unsupported'?'Desteklenmiyor':module.status==='unavailable'?'Kullanılamıyor':'Hata'}`));
    if(module.reason)note.append(E('div','',module.reason));if(module.backend)note.append(E('div','',`Motor: ${module.backend}`));if(module.truncated)note.append(E('div','','Kayıt sınırına ulaşıldı; sonuçlar kısmi.'));right.append(note);
  });
  grid.append(left,right);container.append(grid);
  if(s.description){const details=E('details');details.append(E('summary','muted small','Dosya tanıma ayrıntıları'));details.append(E('pre','code-output',s.description));container.append(details);}
  if(s.build_notes){const details=E('details');details.append(E('summary','muted small','Build notları ve kimlik bilgileri'));details.append(E('pre','code-output',s.build_notes));container.append(details);}
  if(s.observations.length)container.append(E('div','notice',`Kanıt gerektiren ${s.observations.length} gözlem bulundu. `+s.observations.map(o=>o.interpretation).join(' ')));
  container.append(E('div','notice good','Bulgular tek başına zararlılık hükmü değildir. Göstergeleri dosyanın amacı ve bağlamıyla birlikte değerlendir.'));
}
async function tab(name) {
  if(!state.summary)return;
  clearTimeout(searchTimer);state.tab=name;state.offset=0;state.viewRequest++;
  document.querySelectorAll('[data-tab]').forEach(el=>{const selected=el.dataset.tab===name;el.classList.toggle('active',selected);el.setAttribute('aria-selected',selected);el.tabIndex=selected?0:-1;});
  $('result-content').setAttribute('aria-labelledby',`tab-${name}`);
  show('overview-view',name==='overview');show('table-view',!['overview','hex'].includes(name));show('hex-view',name==='hex');
  if(name==='overview'){overview();return;}
  if(name==='hex'){await loadHex();return;}
  $('result-search').value='';
  const select=$('result-kind');select.replaceChildren(new Option('Tüm türler',''));
  (filterDefs[name]||[]).forEach(([value,label])=>select.append(new Option(label,value)));
  select.disabled=!(filterDefs[name]?.length);
  await loadTable();
}
async function loadTable() {
  const request=++state.viewRequest,job=state.job,tabName=state.tab;
  if(!tableDefs[tabName])return;
  const params=new URLSearchParams({tab:tabName,q:$('result-search').value,kind:$('result-kind').value,offset:state.offset,limit:100});
  const data=await api(`/api/jobs/${job}/view?${params}`);
  if(request!==state.viewRequest || state.job!==job || state.tab!==tabName)return;
  state.rows=data.rows;state.total=data.total;
  const module=state.summary.modules[tabName==='strings'?'strings':tabName==='disassembly'?'disassembly':'elf'];
  $('module-note').textContent=tabName==='indicators'?'URL, alan adı, IP, dosya yolu ve hata metni. Kanıtlar bağlam gerektirir; dizgi başlangıç ofsetleri gösterilir.':module?.reason || module?.limits || (tabName==='disassembly'?'Sanal adresler ve çözümlenen komutlar. Relocation uygulanmaz.':'Sonuçlar dosyadan elde edilen gerçek kayıtlardır.');
  const container=$('table-container');container.replaceChildren();
  if(!data.rows.length){container.append(E('div','empty-state', $('result-search').value?'Aramana uyan kayıt bulunamadı.':module?.reason || 'Bu görünüm için kayıt bulunmuyor.'));}
  else {
    const table=E('table'),head=E('thead'),tr=E('tr');tableDefs[tabName].forEach(([,label])=>{const th=E('th','',label);th.scope='col';tr.append(th);});head.append(tr);table.append(head);const body=E('tbody');
    buildRows(tableDefs[tabName],data.rows).forEach(values=>{const row=E('tr');values.forEach((value,i)=>row.append(E('td',tableDefs[tabName][i][0]==='mnemonic'?'mnemonic':(['text','evidence','name'].includes(tableDefs[tabName][i][0])?'text-cell':''),value)));body.append(row);});table.append(body);container.append(table);
  }
  $('row-count').textContent=data.total?`${count(state.offset+1)}–${count(Math.min(state.offset+100,data.total))} / ${count(data.total)} kayıt`:'0 kayıt';
  $('prev-page').disabled=state.offset===0;$('next-page').disabled=state.offset+100>=data.total;
}
async function loadHex() {
  const job=state.job,request=++state.viewRequest;
  const address=$('hex-address').value;
  const data=await api(`/api/jobs/${job}/view?${new URLSearchParams({tab:'hex',address})}`);
  if(request!==state.viewRequest||state.job!==job||state.tab!=='hex')return;
  $('hex-output').textContent=data.text || 'Bu ofsette veri bulunmuyor.';$('hex-address').value=`0x${data.address.toString(16)}`;
  $('hex-next').disabled=data.address+4096>=data.size;
}
async function refreshHistory() {const data=await api('/api/history');state.history=data.jobs;$('history-count').textContent=data.jobs.length;renderHistory();}
function historyRow(item) {
  const button=E('button','history-row'),tile=E('span','file-tile');tile.append(icon(item.mode==='reverse'?'code':'file'));const body=E('span','history-file');body.append(E('strong','',item.name),E('small','',`${item.mode==='reverse'?'Tersine mühendislik':'Statik analiz'}${item.summary?' · '+formatSize(item.summary.file.size)+' · '+item.summary.format:''}`));button.append(tile,body,E('span','muted small',statusLabel(item.state)),icon('arrow'));
  button.addEventListener('click',safe(async()=>{if(state.busy&&state.job!==item.id){toast('Önce etkin analizin tamamlanmasını bekle veya iptal et.');return;}state.job=item.id;state.rendered=null;state.summary=null;show('results',false);page('workspace');await pollJob();(item.state==='completed'?$('results'):$('progress-panel')).scrollIntoView({behavior:'smooth',block:'start'});}));return button;
}
function renderHistory() {
  ['recent-list','history-list'].forEach((id,i)=>{const container=$(id);container.replaceChildren();const items=i?state.history:state.history.slice(0,3);if(!items.length){const empty=E('div','empty-state');empty.append(E('strong','','Henüz bir analiz yok.'),E('span','','İlk dosyanı ekleyerek çalışma alanını oluşturmaya başla.'));container.append(empty);}else items.forEach(item=>container.append(historyRow(item)));});
}
async function exportReport(format) {
  if(!state.job)return;
  const blob=await api(`/api/jobs/${state.job}/report?format=${format}`,{blob:true});
  const url=URL.createObjectURL(blob),link=E('a');link.href=url;link.download=`rewb-${state.summary.file.hashes.sha256.slice(0,12)}.${format==='md'?'md':'json'}`;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);toast('Rapor indirildi.');
}
function capabilities(data) {
  $('version').textContent=`v${data.version}`;const container=$('capabilities');container.replaceChildren();
  const descriptions={file:'Uzantıdan bağımsız dosya tanıma',readelf:'ELF bilgileri ve yapılandırılmış tablo yedeği',objdump:'Capstone yoksa yerel disassembly',podman:'İsteğe bağlı yalıtılmış dinamik analiz',capstone:'x86, x86-64, ARM ve AArch64 disassembly',elftools:'Yapılandırılmış ELF ayrıştırıcısı',mcp:'MCP sunucusu bağlantısı ve araç keşfi'};
  Object.entries({...data.tools,...data.packages}).forEach(([name,available])=>{const row=E('div','capability-row'),body=E('div');body.append(E('strong','',name),E('small','',descriptions[name]));row.append(body,E('span',`capability-state${available?'':' missing'}`,available?'Kullanılabilir':'Kurulu değil'));container.append(row);});
  container.append(E('div','notice','PE/Mach-O dosyalarında bu sürüm hash, tanıma, strings ve hex sunar. Ayrıntılı yapısal analiz ve disassembly ELF içindir. Kullanılabilirlik, tüm mimarilerin yerel araç tarafından desteklendiği anlamına gelmez.'));
}
async function refreshMCP() {
  const data=await api('/api/mcp');state.mcp=data;
  $('mcp-connection').textContent=({connected:'Sunucu bağlı',connecting:'Bağlanıyor…',disconnected:'Bağlı değil'})[data.state]||data.state;
  $('mcp-message').textContent=data.error || data.message || '';
  $('mcp-dot').classList.toggle('neutral',data.state!=='connected');
  $('mcp-connect').disabled=data.state!=='disconnected';$('mcp-refresh').disabled=data.state!=='connected';$('mcp-disconnect').disabled=data.state==='disconnected';
  const tools=$('mcp-tools');tools.replaceChildren();
  if(!data.tools?.length)tools.append(E('div','empty-state',data.state==='connected'?'Sunucu araç sunmadı.':'Bağlantı kurulduğunda keşfedilen araçlar burada görünür.'));
  else data.tools.forEach(tool=>{const button=E('button',`tool-card${state.tool?.name===tool.name?' selected':''}`);button.append(E('strong','',tool.name),E('small','',tool.description || 'Açıklama sunulmadı.'));button.addEventListener('click',()=>selectTool(tool));tools.append(button);});
  if(state.tool&&!data.tools?.some(t=>t.name===state.tool.name)) {state.tool=null;$('mcp-tool-title').textContent='Bir araç seç';$('mcp-tool-description').textContent='';$('mcp-schema').textContent='{}';}
  $('mcp-prepare').disabled=!state.tool?.callable || data.state!=='connected' || !!data.busy;
  if(data.result)$('mcp-output').textContent=JSON.stringify(data.result,null,2);
  if(data.error)$('mcp-output').textContent=data.error;
}
function selectTool(tool) {state.tool=tool;$('mcp-tool-title').textContent=tool.name;$('mcp-tool-description').textContent=tool.description || '';$('mcp-schema').textContent=JSON.stringify(tool.inputSchema,null,2);$('mcp-prepare').disabled=!tool.callable || !!state.mcp?.busy;if(tool.restriction)toast(tool.restriction);document.querySelectorAll('.tool-card').forEach(el=>el.classList.toggle('selected',el.querySelector('strong').textContent===tool.name));}
function approval(title,description,payload,action) {
  state.pending=action;$('approval-title').textContent=title;$('approval-description').textContent=description;$('approval-payload').textContent=payload;$('approval-check').checked=false;$('approval-confirm').disabled=true;$('approval-dialog').showModal();
}
async function prepareMCP() {
  if(!state.tool)return;
  let args;try{args=JSON.parse($('mcp-arguments').value);}catch(_){throw new Error('Geçerli bir JSON nesnesi yaz.');}
  const plan=await post('/api/mcp/prepare',{name:state.tool.name,arguments:args});
  approval('MCP çağrısını onayla',`Alıcı: ${plan.destination}. Aşağıda gönderilecek tam parametreler var. Parametrelere yazdığın hassas bilgiler sunucuya iletilir.`,plan.payload,async()=>{await post('/api/mcp/call',{ticket:plan.ticket,confirmed:true});toast('Onaylanan çağrı gönderildi.');await refreshMCP();});
}
async function refreshDynamic() {const data=await api('/api/dynamic');$('dynamic-message').textContent=data.message;$('dynamic-cancel').disabled=data.state!=='running';$('dynamic-prepare').disabled=!state.summary||state.busy||data.state==='running';if(data.result)$('dynamic-output').textContent=JSON.stringify(data.result,null,2);}
async function prepareDynamic() {
  if(!state.summary)throw new Error('Önce bir dosyanın statik analizini tamamla.');
  const plan=await post('/api/dynamic/prepare',{id:state.job});
  approval('Yalıtılmış çalıştırmayı onayla','Bu işlem örneği geçici, ağ erişimi kapalı bir container içinde çalıştırır. Komutu ve kaynak sınırlarını incele.',JSON.stringify(plan.plan,null,2),async()=>{await post('/api/dynamic/run',{ticket:plan.ticket,confirmed:true});await refreshDynamic();});
}
async function tick() {
  if(polling||!token)return;polling=true;
  try{if(state.busy)await pollJob();if(state.page==='mcp')await refreshMCP();if(state.page==='dynamic')await refreshDynamic();}
  catch(e){error(e.message);}finally{polling=false;}
}
async function initialize() {
  document.querySelectorAll('[data-page]').forEach(el=>el.addEventListener('click',()=>page(el.dataset.page)));
  document.querySelectorAll('[data-mode]').forEach(el=>el.addEventListener('click',()=>setMode(el.dataset.mode)));
  document.querySelectorAll('[data-mode-shortcut]').forEach(el=>el.addEventListener('click',()=>{page('workspace');setMode(el.dataset.modeShortcut);}));
  document.querySelector('.brand').addEventListener('click',e=>{e.preventDefault();page('workspace');});
  $('all-history').addEventListener('click',()=>page('history'));$('dismiss-error').addEventListener('click',()=>show('error-banner',false));
  $('file-input').addEventListener('change',e=>choose(e.target.files[0]||null));
  $('remove-file').addEventListener('click',()=>{choose(null);$('file-input').value='';});
  ['dragenter','dragover'].forEach(name=>$('dropzone').addEventListener(name,e=>{e.preventDefault();$('dropzone').classList.add('dragover');}));
  ['dragleave','drop'].forEach(name=>$('dropzone').addEventListener(name,e=>{e.preventDefault();$('dropzone').classList.remove('dragover');}));
  $('dropzone').addEventListener('drop',e=>{if(e.dataTransfer.files.length>1)toast('İlk dosya seçildi. Her analizde bir dosya incelenir.');choose(e.dataTransfer.files[0]||null);});
  window.addEventListener('dragover',e=>e.preventDefault());window.addEventListener('drop',e=>e.preventDefault());
  $('analyze').addEventListener('click',safe(start));
  ['cancel-analysis','dynamic-cancel'].forEach(id=>$(id).addEventListener('click',safe(async()=>{await post('/api/cancel');toast('İptal istendi.');})));
  document.querySelectorAll('[data-tab]').forEach(el=>{el.addEventListener('click',safe(()=>tab(el.dataset.tab)));el.addEventListener('keydown',e=>{if(!['ArrowRight','ArrowLeft','Home','End'].includes(e.key))return;e.preventDefault();const tabs=[...document.querySelectorAll('[data-tab]')],i=tabs.indexOf(el),next=e.key==='Home'?0:e.key==='End'?tabs.length-1:(i+(e.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tabs[next].focus();safe(()=>tab(tabs[next].dataset.tab))();});});
  $('result-search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(safe(async()=>{state.offset=0;await loadTable();}),220);});
  $('result-kind').addEventListener('change',safe(async()=>{state.offset=0;await loadTable();}));
  $('prev-page').addEventListener('click',safe(async()=>{state.offset=Math.max(0,state.offset-100);await loadTable();}));
  $('next-page').addEventListener('click',safe(async()=>{state.offset+=100;await loadTable();}));
  $('copy-results').addEventListener('click',safe(()=>copy([tableDefs[state.tab].map(([,label])=>label),...buildRows(tableDefs[state.tab],state.rows)].map(row=>row.join('\t')).join('\n'))));
  $('hex-go').addEventListener('click',safe(loadHex));$('hex-address').addEventListener('keydown',e=>{if(e.key==='Enter')safe(loadHex)();});
  $('hex-next').addEventListener('click',safe(async()=>{const position=Number($('hex-address').value);if(!Number.isFinite(position))throw new Error('Geçerli bir ofset gir.');$('hex-address').value=`0x${(position+4096).toString(16)}`;await loadHex();}));
  $('copy-hex').addEventListener('click',safe(()=>copy($('hex-output').textContent)));
  document.querySelectorAll('.export-button').forEach(el=>el.addEventListener('click',safe(()=>exportReport(el.dataset.format))));
  [['mcp-connect','/api/mcp/connect'],['mcp-disconnect','/api/mcp/disconnect'],['mcp-refresh','/api/mcp/refresh']].forEach(([id,path])=>$(id).addEventListener('click',safe(async()=>{await post(path);await refreshMCP();})));
  $('mcp-prepare').addEventListener('click',safe(prepareMCP));$('dynamic-prepare').addEventListener('click',safe(prepareDynamic));
  $('approval-check').addEventListener('change',()=>{$('approval-confirm').disabled=!$('approval-check').checked;});
  $('approval-cancel').addEventListener('click',()=>{state.pending=null;$('approval-dialog').close();});
  $('approval-dialog').addEventListener('cancel',()=>{state.pending=null;});
  $('approval-confirm').addEventListener('click',safe(async()=>{if(!$('approval-check').checked||!state.pending)return;const action=state.pending;state.pending=null;$('approval-dialog').close();await action();}));
  renderHistory();
  if(!token){show('session-warning');return;}
  const data=await api('/api/status');capabilities(data);await refreshHistory();
  if(data.active){state.job=data.active;state.busy=true;await pollJob();}
  setInterval(tick,1000);
}
initialize().catch(e=>error(e.message || 'Başlatma tamamlanamadı.'));
}
