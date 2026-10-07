(function(){
const P=__PARAMS__;
const u=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
let key=null;
async function derive(pw){
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:u(P.s),iterations:P.n,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
}
/* 파일 형식: 12바이트 IV + AES-GCM 암호문. 평문은 gzip으로 압축된 JSON */
async function load(name){
  const r=await fetch('data/'+name+'.enc?v='+P.v);
  if(!r.ok)throw new Error(name+' '+r.status);
  const a=new Uint8Array(await r.arrayBuffer());
  const gz=await crypto.subtle.decrypt({name:'AES-GCM',iv:a.slice(0,12)},key,a.slice(12));
  const text=await new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  return JSON.parse(text);
}
async function open(pw){
  key=await derive(pw);
  const [manifest,app]=await Promise.all([load('manifest'),load('app')]);
  window.MN={manifest,get:load};
  return app;
}
function show(p){
  document.getElementById('lock').remove();
  const app=document.getElementById('app');app.innerHTML=p.html;app.hidden=false;
  const s=document.createElement('script');s.textContent=p.js;document.body.appendChild(s);
}
async function tryOpen(pw,remember){
  const p=await open(pw);
  if(remember){try{sessionStorage.setItem('mn-pw',pw)}catch(e){}}
  show(p);
}
let saved=null;try{saved=sessionStorage.getItem('mn-pw')}catch(e){}
if(saved){tryOpen(saved,false).catch(()=>{try{sessionStorage.removeItem('mn-pw')}catch(e){}})}
const f=document.getElementById('lockForm'),b=document.getElementById('go'),err=document.getElementById('err'),inp=document.getElementById('pw');
const L0=b.textContent;
f.addEventListener('submit',async e=>{
  e.preventDefault();err.textContent='';b.disabled=true;b.textContent='확인 중…';
  try{await tryOpen(inp.value,document.getElementById('keep').checked)}
  catch(x){err.textContent='비밀번호가 맞지 않습니다.';inp.select();b.disabled=false;b.textContent=L0}
});
})();
