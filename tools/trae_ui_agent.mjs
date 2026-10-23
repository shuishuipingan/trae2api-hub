#!/usr/bin/env node
import fs from 'fs';import os from 'os';import path from 'path';
const repo=path.dirname(new URL(import.meta.url).pathname).replace(/^\/([A-Za-z]:)/,'$1');
const base=JSON.parse(fs.readFileSync(path.join(repo,'aha_packet.json'),'utf8'));
const token=fs.readFileSync(path.join(os.homedir(),'.trae-cn','trae-jwt-token'),'utf8').trim();
let uid='';
try{const pl=JSON.parse(Buffer.from(token.split('.')[1]||'', 'base64url').toString('utf8'));uid=String(pl?.data?.id||'');}catch(e){}

const prompt=process.argv[2]||'只回答好';const port=process.env.TRAE_CDP_PORT||'9335';
const scrub=o=>{if(o&&typeof o==='object')for(const k of Object.keys(o)){if(k==='token')o[k]=token;else scrub(o[k]);}};scrub(base);
if(uid){base.params[0].params.user_info.user_id=uid;for(const key of ['user_id','icube_uid','biz_user_id'])if(base.params[0].params.common_params)base.params[0].params.common_params[key]=uid;}
const ts=await (await fetch('http://127.0.0.1:'+port+'/json/list')).json();const t=ts.find(x=>x.title&&x.title.startsWith('Agent'));if(!t)throw Error('no Agent page');
const ws=new WebSocket(t.webSocketDebuggerUrl);let id=1;const q=new Map();ws.addEventListener('message',e=>{const m=JSON.parse(e.data);if(m.id&&q.has(m.id)){q.get(m.id)(m);q.delete(m.id);}});await new Promise((r,j)=>{ws.addEventListener('open',r);ws.addEventListener('error',j);});
const cdp=(m,pa={})=>new Promise(r=>{const i=id++;q.set(i,r);ws.send(JSON.stringify({id:i,method:m,params:pa}));});
const ev=async ex=>(await cdp('Runtime.evaluate',{expression:ex,awaitPromise:true,returnByValue:true})).result?.result?.value;
const clickSend=async()=>{
 const r=await ev("(()=>{const es=[...document.querySelectorAll('[contenteditable=true]')];const e=es.find(x=>x.offsetParent!==null)||es[0];if(!e)return 'no editor';e.focus();document.execCommand('insertText',false,"+JSON.stringify(prompt)+");return 'typed'})()");
 await new Promise(r=>setTimeout(r,400));
 // press Enter
 await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
 await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
 return r;
};
const aha=async(method,data,wait=1500)=>{const p=structuredClone(base);p.id=method+'-'+Date.now();const x=p.params[0];x.channel_id=crypto.randomUUID();x.params.method=method;x.params.data=data;const ex='(async()=>{const tr=await window.vscode.ahaIpc.connect("ai-agent");const out=[];tr.on("message",m=>out.push(String(m)));tr.send('+JSON.stringify(JSON.stringify(p))+');await new Promise(r=>setTimeout(r,'+wait+'));return out})()';const rs=await ev(ex);for(const s of rs||[]){try{const o=JSON.parse(s);if(o?.result?.params?.data)return o.result.params.data;}catch{}}return null;};
const typed=await clickSend();
let answer='';let lastSid='';
for(let i=0;i<12;i++){
 await new Promise(r=>setTimeout(r,2500));
 const ls=await aha('list_chat_sessions',{page_size:20},1200);
 const items=ls?.data?.items||ls?.items||[];
 if(items.length){lastSid=items[0].chat_session_id;}
 const ms=await aha('get_messages',{chat_session_id:lastSid,session_id:lastSid},1200);
 const arr=ms?.data?.items||ms?.items||[];
 const last=arr[arr.length-1];
 if(last?.role==='assistant'&&last.status==='completed'){
  try{const c=JSON.parse(last.content);for(const x of c.messages||[]){if(x.type==='plan_item'&&x.plan_item?.tool_call_info?.name==='finish'){answer=x.plan_item.tool_call_info.params?.summary||'';}}}catch(e){}
  if(answer)break;
 }
}
console.log(JSON.stringify({ok:!!answer,text:answer,session:lastSid,typed}));ws.close();
