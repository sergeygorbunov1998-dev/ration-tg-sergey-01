import assert from 'node:assert/strict';
import app,{renderPost,bar} from './index.mjs';

const kv=new Map(), sent=[];
const STATE={
 get:async(k,kind)=>{const v=kv.get(k)||null;return kind==='json'&&v?JSON.parse(v):v},
 put:async(k,v)=>{kv.set(k,String(v))},
 delete:async(k)=>kv.delete(k)
};
const env={TELEGRAM_BOT_TOKEN:'test-telegram-token',TELEGRAM_CHAT_ID:'@ration_sergey_post',OWNER_PASSWORD:'this is a very long private password',STATE,GOAL_CAL:'2350',GOAL_P:'175'};
const base='https://ration-test.example';
const invoke=(url,options={})=>app.fetch(new Request(base+url,options),env);
const rpc=(method,params,id=1,auth='')=>invoke('/mcp',{method:'POST',headers:{'content-type':'application/json',...(auth?{authorization:'Bearer '+auth}:{})},body:JSON.stringify({jsonrpc:'2.0',id,method,params})});
const makeChallenge=async(text)=>{const bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text)));return Buffer.from(bytes).toString('base64url')};
let r=await invoke('/health');assert.equal((await r.json()).ready,true);
r=await rpc('initialize',{protocolVersion:'2025-06-18',capabilities:{},clientInfo:{name:'test',version:'1'}});
assert.equal(r.status,200);assert.equal((await r.json()).result.serverInfo.name,'ration-telegram');
r=await rpc('tools/list');assert.equal(r.status,200);
const tools=(await r.json()).result.tools;
const pub=tools.find(x=>x.name==='publish_meal');
assert.deepEqual(pub._meta['openai/fileParams'],['photos']);
assert.equal(pub.inputSchema.properties.photos.items.required.length,2);
r=await rpc('tools/call',{name:'get_daily_progress',arguments:{}});
assert.equal(r.status,401,'Write/read actions must require OAuth');
r=await invoke('/.well-known/oauth-protected-resource');assert.equal((await r.json()).resource,base+'/mcp');
r=await invoke('/.well-known/oauth-authorization-server');const oauth=await r.json();
assert.ok(oauth.code_challenge_methods_supported.includes('S256'));
const redirect='https://chatgpt.com/connector_platform_oauth_redirect';
r=await invoke('/oauth/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:[redirect]})});
assert.equal(r.status,201);const client=(await r.json()).client_id;assert.ok(client);
r=await invoke('/oauth/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:['https://attacker.example/callback']})});
assert.equal(r.status,400);
const verifier='k'.repeat(48),challenge=await makeChallenge(verifier);
const params=new URLSearchParams({response_type:'code',client_id:client,redirect_uri:redirect,state:'abc',code_challenge:challenge,code_challenge_method:'S256',resource:base+'/mcp'});
r=await invoke('/oauth/authorize?'+params.toString());
assert.equal(r.status,200);assert.match(await r.text(),/Рацион/);
const authorizeForm=new URLSearchParams({client_id:client,redirect_uri:redirect,state:'abc',code_challenge:challenge,resource:base+'/mcp',password:'bad password'});
r=await invoke('/oauth/authorize',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:authorizeForm});
assert.equal(r.status,403,'OAuth must reject wrong owner password');
authorizeForm.set('password',env.OWNER_PASSWORD);
r=await invoke('/oauth/authorize',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:authorizeForm,redirect:'manual'});
assert.equal(r.status,302);const location=new URL(r.headers.get('Location'));assert.equal(location.searchParams.get('state'),'abc');const code=location.searchParams.get('code');assert.ok(code);
const grant=new URLSearchParams({grant_type:'authorization_code',code,client_id:client,redirect_uri:redirect,code_verifier:'invalid-verifier',resource:base+'/mcp'});
r=await invoke('/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:grant});assert.equal(r.status,400);
grant.set('code_verifier',verifier);
r=await invoke('/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:grant});
assert.equal(r.status,200);const auth=(await r.json()).access_token;assert.ok(auth);
r=await invoke('/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:grant});
assert.equal(r.status,400,'Authorization code must be single use');
const original=globalThis.fetch;
globalThis.fetch=async(url,options={})=>{
 const addr=String(url);
 if(addr==='https://files.oaiusercontent.com/meal.jpg')return new Response(new Uint8Array([0xff,0xd8,0xff,0xe0,1,2,3]),{status:200,headers:{'content-type':'image/jpeg'}});
 if(addr.startsWith('https://api.telegram.org/')){
  const endpoint=addr.split('/').at(-1);sent.push({endpoint,options});
  if(endpoint==='sendPhoto'||endpoint==='sendMediaGroup'||endpoint==='sendMessage')return Response.json({ok:true,result:endpoint==='sendMediaGroup'?[{message_id:1321}]:{message_id:1321}});
 }
 throw Error('Unexpected outbound URL '+addr);
};
try{
 const photo={download_url:'https://files.oaiusercontent.com/meal.jpg',file_id:'file_123',mime_type:'image/jpeg',file_name:'meal.jpg'};
 const args={description:'Обед\nТунец 177 г (230 ккал, 51 г белка)\nДжемелли 100 г сухих (387 ккал, 12,8 г белка)',calories:617,protein:64.1,date:'2026-11-23',photos:[photo],idempotency_key:'sample-meal-2026-11-23'};
 r=await rpc('tools/call',{name:'publish_meal',arguments:args},7,auth);
 assert.equal(r.status,200);
 let published=JSON.parse((await r.json()).result.content[0].text);
 assert.equal(published.ok,true);
 assert.equal(published.photos,1);
 assert.equal(published.url,'https://t.me/ration_sergey_post/1321');
 assert.equal(sent.filter(x=>x.endpoint==='sendPhoto').length,1);
 assert.equal(sent[0].options.body.get('chat_id'),'@ration_sergey_post');
 assert.match(sent[0].options.body.get('caption'),/🟩/u);
 assert.equal((await STATE.get('daily:2026-11-23','json')).cal,617);
 r=await rpc('tools/call',{name:'publish_meal',arguments:args},8,auth);
 assert.equal((await r.json()).result.isError,false);
 assert.equal(sent.filter(x=>x.endpoint==='sendPhoto').length,1,'Repeat must not create a new Telegram message');
 r=await rpc('tools/call',{name:'get_daily_progress',arguments:{date:'2026-11-23'}},9,auth);
 assert.equal(JSON.parse((await r.json()).result.content[0].text).protein,64.1);
 r=await rpc('tools/call',{name:'publish_meal',arguments:{...args,idempotency_key:'bad-url',photos:[{...photo,download_url:'https://169.254.169.254/latest'}]}},10,auth);
 assert.equal((await r.json()).result.isError,true,'Must reject SSRF image source');
 r=await rpc('tools/call',{name:'set_daily_progress',arguments:{date:'2026-11-23',calories:1568,protein:143.7}},11,auth);
 assert.equal(JSON.parse((await r.json()).result.content[0].text).calories,1568);
 const summary=renderPost({description:'Еда',calories:100,protein:20},{date:'2026-11-23',cal:1568,protein:143.7,goalCal:2350,goalP:175,count:3});
 assert.match(summary.msg,/1 668|1 668/);
 assert.equal(bar(2350,2350),'🟩'.repeat(10));
 console.log('Custom MCP: OAuth PKCE, tool schema fileParams, file upload, Telegram sendPhoto, daily bars, SSRF prevention and deduplication: OK');
}finally{globalThis.fetch=original}
