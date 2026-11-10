// Only this generic access screen is public. The application itself is encrypted.
const encoder=new TextEncoder(),decoder=new TextDecoder();
const entry=document.getElementById('entry'),workspace=document.getElementById('workspace');
const input=document.getElementById('access'),error=document.getElementById('gate-error');
const submit=document.getElementById('unlock'),status=document.getElementById('gate-status');
let active=null,cleanup=null,styleLink=null,moduleURL=null,unlocking=false,idleTimer,hiddenTimer;
const bytes64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
const abortError=()=>new DOMException('Session ended','AbortError');

async function decompress(data){return new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer());}
async function decrypt(data,key,aad){
 if(data.byteLength<28)throw new Error('Invalid data');
 const bytes=new Uint8Array(data);
 return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(0,12),additionalData:encoder.encode(aad),tagLength:128},key,bytes.slice(12)));
}
function objectURLPath(value){
 if(!/^objects\/[0-9a-f]{2}\/[0-9a-f]{32}\.bin$/.test(value))throw new Error('Invalid resource path');
 return new URL(value,location.href);
}
async function fetchBytes(path,signal){const r=await fetch(objectURLPath(path),{cache:'no-store',signal});if(!r.ok)throw new Error('Resource unavailable');return r.arrayBuffer();}

function sessionAPI(key,catalog){
 let live=true,generation=0;const controller=new AbortController(),jsonCache=new Map(),mediaCache=new Map(),urls=new Set();
 async function file(logical){
  if(!live)throw abortError();
  const meta=catalog[logical];if(!meta)throw new Error('Resource not included');
  const parts=[];
  for(let i=0;i<meta.chunks.length;i++){
   const c=meta.chunks[i],encrypted=await fetchBytes(c.file,controller.signal);
   const decoded=await decrypt(encrypted,key,`lumen-file-v1\0${logical}\0${i}`);
   const part=c.encoding==='gzip'?await decompress(decoded):decoded;
   if(!live)throw abortError();parts.push(part);
  }
  const result=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let pos=0;
  for(const part of parts){result.set(part,pos);pos+=part.length;}
  if(result.length!==meta.bytes||hex(new Uint8Array(await crypto.subtle.digest('SHA-256',result)))!==meta.sha256)throw new Error('Resource identity mismatch');
  if(!live)throw abortError();return result;
 }
 async function json(logical){
  if(!live)throw abortError();
  if(!jsonCache.has(logical))jsonCache.set(logical,file(logical).then(data=>JSON.parse(decoder.decode(data))).catch(e=>{jsonCache.delete(logical);throw e;}));
  return jsonCache.get(logical);
 }
 async function text(logical){return decoder.decode(await file(logical));}
 async function asset(logical){
  if(!live)throw abortError();
  const current=generation;
  if(!mediaCache.has(logical))mediaCache.set(logical,(async()=>{
   const data=await file(logical);if(!live||current!==generation)throw abortError();
   const url=URL.createObjectURL(new Blob([data],{type:catalog[logical].mime}));urls.add(url);return url;
  })().catch(e=>{mediaCache.delete(logical);throw e;}));
  return mediaCache.get(logical);
 }
 async function download(logical,name){
  const data=await file(logical);if(!live)throw abortError();
  const url=URL.createObjectURL(new Blob([data],{type:catalog[logical].mime}));urls.add(url);
  const a=document.createElement('a');a.href=url;a.download=name||logical.split('/').pop();a.click();
  setTimeout(()=>{URL.revokeObjectURL(url);urls.delete(url);},30000);
 }
 function releaseMedia(){generation++;for(const url of urls)URL.revokeObjectURL(url);urls.clear();mediaCache.clear();}
 function dispose(){live=false;controller.abort();releaseMedia();jsonCache.clear();key=null;catalog=null;}
 return {json,text,asset,download,releaseMedia,dispose,lock,catalog:()=>Object.keys(catalog||{}),fingerprint:logical=>catalog?.[logical]?.sha256,isLive:()=>live};
}

function lock(){
 clearTimeout(idleTimer);clearTimeout(hiddenTimer);
 if(cleanup){try{cleanup();}catch{}cleanup=null;}
 if(active){active.dispose();active=null;}
 workspace.replaceChildren();workspace.hidden=true;entry.hidden=false;
 styleLink?.remove();styleLink=null;if(moduleURL)URL.revokeObjectURL(moduleURL);moduleURL=null;
 document.title='Lumen';history.replaceState(null,'',location.pathname);input.value='';
 error.textContent='';status.textContent='内容将在本机解锁。';
}
function activity(){if(active){clearTimeout(idleTimer);idleTimer=setTimeout(lock,15*60*1000);}}
for(const event of ['pointerdown','keydown','touchstart'])document.addEventListener(event,activity,{passive:true});
document.addEventListener('visibilitychange',()=>{clearTimeout(hiddenTimer);if(active&&document.hidden)hiddenTimer=setTimeout(lock,2*60*1000);});
addEventListener('pagehide',lock);
document.getElementById('show-password').onclick=()=>{
 const show=input.type==='password';input.type=show?'text':'password';
 document.getElementById('show-password').setAttribute('aria-pressed',String(show));
 document.getElementById('show-password').setAttribute('aria-label',show?'隐藏密码':'显示密码');input.focus();
};

document.getElementById('unlock-form').addEventListener('submit',async event=>{
 event.preventDefault();if(unlocking)return;
 if(!input.value){error.textContent='请输入访问密码。';input.focus();return;}
 if(!crypto.subtle||!window.DecompressionStream){error.textContent='请使用更新版本的浏览器，并通过 HTTPS 打开。';return;}
 unlocking=true;submit.disabled=true;document.getElementById('busy').hidden=false;error.textContent='';status.textContent='正在打开空间…';
 let api=null,root=null;
 try{
  const password=encoder.encode(input.value);input.value='';
  const response=await fetch('vault.json',{cache:'no-store'});if(!response.ok)throw new Error('Descriptor unavailable');
  const config=await response.json();
  if(config.version!==1||config.kdf.name!=='PBKDF2'||config.kdf.hash!=='SHA-256'||config.kdf.iterations<100000||config.kdf.iterations>5000000)throw new Error('Unsupported format');
  const material=await crypto.subtle.importKey('raw',password,'PBKDF2',false,['deriveKey']);password.fill(0);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes64(config.kdf.salt),iterations:config.kdf.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const encrypted=await fetchBytes(config.root);
  root=JSON.parse(decoder.decode(await decompress(await decrypt(encrypted,key,'lumen-root-v1'))));
  const rawKey=bytes64(root.data_key);delete root.data_key;
  const dataKey=await crypto.subtle.importKey('raw',rawKey,{name:'AES-GCM'},false,['decrypt']);rawKey.fill(0);
  api=sessionAPI(dataKey,root.catalog);
  const cssURL=URL.createObjectURL(new Blob([root.app.css],{type:'text/css'}));
  styleLink=document.createElement('link');styleLink.rel='stylesheet';styleLink.href=cssURL;document.head.append(styleLink);
  await new Promise((resolve,reject)=>{styleLink.onload=resolve;styleLink.onerror=reject;});URL.revokeObjectURL(cssURL);
  // Template and code are build-owned authenticated application files, never chat HTML.
  const template=document.createElement('template');template.innerHTML=root.app.html;
  workspace.replaceChildren(template.content.cloneNode(true));
  moduleURL=URL.createObjectURL(new Blob([root.app.js],{type:'text/javascript'}));
  const app=await import(moduleURL);root=null;active=api;
  cleanup=await app.mount(api,workspace);
  entry.hidden=true;workspace.hidden=false;document.title='Lumen';activity();
 }catch(e){
  api?.dispose();root=null;workspace.replaceChildren();styleLink?.remove();styleLink=null;
  if(moduleURL)URL.revokeObjectURL(moduleURL);moduleURL=null;active=null;
  error.textContent='密码不正确，或页面资源暂不可用。请检查后重试。';status.textContent='内容仍保持锁定。';
 }finally{unlocking=false;submit.disabled=false;document.getElementById('busy').hidden=true;}
});
