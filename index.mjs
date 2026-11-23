/**
 * Рацион+ → Telegram, custom MCP plugin for ChatGPT.
 * No external scheduler, OpenAI API key, or Upload-Post subscription needed.
 * ChatGPT provides attached image files via openai/fileParams.
 * Cloudflare Worker signs single-user OAuth credentials and stores day totals in KV.
 */
const TZ='Europe/Moscow';
const jr=(x,status=200,headers={})=>new Response(JSON.stringify(x),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers}});
const err=(msg,status=400)=>jr({error:msg},status);
const round=x=>Math.round(Number(x)*10)/10;
const nice=x=>round(x).toLocaleString('ru-RU',{maximumFractionDigits:1});
const bar=(v,max)=>'🟩'.repeat(Math.min(10,Math.max(0,Math.round(10*v/max))))+'⬜'.repeat(Math.max(0,10-Math.min(10,Math.max(0,Math.round(10*v/max)))));
const nowDate=()=>new Intl.DateTimeFormat('en-CA',{timeZone:TZ,day:'2-digit',month:'2-digit',year:'numeric'}).format(new Date());
const dailyKey=date=>'daily:'+date;
const safeString=(v,max=4000)=>String(v??'').trim().slice(0,max);
const defaults=env=>({goalCal:Number(env.GOAL_CAL||2350),goalP:Number(env.GOAL_P||175)});
async function day(env,date){
 const d=env.STATE?await env.STATE.get(dailyKey(date),'json'):null;
 return {...defaults(env),cal:d?.cal||0,protein:d?.protein||0,count:d?.count||0,date};
}
function renderPost(args,today){
 const prefix=safeString(args.description,1700);
 const p=round(args.protein),cal=round(args.calories);
 const newCal=round(today.cal+cal),newProtein=round(today.protein+p);
 const goalCal=today.goalCal,goalP=today.goalP;
 const msg=prefix+'\n\n'+nice(cal)+' ккал | '+nice(p)+' г белка'+
 '\n\n📊 Прогресс · '+today.date+
 '\nКалории: '+nice(newCal)+' / '+nice(goalCal)+' ккал'+
 '\n'+bar(newCal,goalCal)+' '+Math.round(newCal/goalCal*100)+'%'+
 '\nБелок: '+nice(newProtein)+' / '+nice(goalP)+' г'+
 '\n'+bar(newProtein,goalP)+' '+Math.round(newProtein/goalP*100)+'%'+
 '\nОсталось: '+nice(Math.max(0,goalCal-newCal))+' ккал · '+nice(Math.max(0,goalP-newProtein))+' г белка';
 return {msg,totals:{cal:newCal,protein:newProtein,count:today.count+1}};
}
const textResult=(body,isError=false)=>({content:[{type:'text',text:typeof body==='string'?body:JSON.stringify(body)}],isError});
const bytesTo64=bytes=>{let s='';for(let i=0;i<bytes.length;i+=8192)s+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const to64=s=>bytesTo64(new TextEncoder().encode(s));
const from64=s=>new TextDecoder().decode(Uint8Array.from(atob(String(s).replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),x=>x.charCodeAt(0)));
const cryptoKey=async env=>crypto.subtle.importKey('raw',new TextEncoder().encode('ration-mcp|'+env.OWNER_PASSWORD+'|'+env.TELEGRAM_BOT_TOKEN),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
async function sign(env,obj){
 const payload=to64(JSON.stringify(obj));
 const signature=bytesTo64(new Uint8Array(await crypto.subtle.sign('HMAC',await cryptoKey(env),new TextEncoder().encode(payload))));
 return payload+'.'+signature;
}
async function verify(env,token,kind){
 if(typeof token!=='string'||token.length>5000)return null;
 const [payload,sig,...extra]=token.split('.');if(!payload||!sig||extra.length)return null;
 let valid=false;
 try{valid=await crypto.subtle.verify('HMAC',await cryptoKey(env),Uint8Array.from(atob(sig.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-sig.length%4)%4)),x=>x.charCodeAt(0)),new TextEncoder().encode(payload))}catch{}
 if(!valid)return null;
 try{const data=JSON.parse(from64(payload));return data.kind===kind&&data.exp>Date.now()/1000?data:null}catch{return null}
}
const site=(req)=>new URL(req.url).origin;
const protectedResource=(req)=>site(req)+'/mcp';
const commonHeaders=(req)=>({'Access-Control-Allow-Origin':site(req),'Vary':'Origin','Access-Control-Allow-Headers':'Content-Type, Authorization, MCP-Protocol-Version','Access-Control-Allow-Methods':'POST,GET,OPTIONS'});
function metaAuth(req){
 const origin=site(req);
 return {issuer:origin,authorization_endpoint:origin+'/oauth/authorize',token_endpoint:origin+'/oauth/token',registration_endpoint:origin+'/oauth/register',
  response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],code_challenge_methods_supported:['S256'],
  token_endpoint_auth_methods_supported:['none'],scopes_supported:['telegram:publish']};
}
function isChatGPTCallback(uri){
 try{const u=new URL(uri);return u.protocol==='https:'&&u.hostname==='chatgpt.com'&&(/^(\/connector\/oauth\/[a-zA-Z0-9_-]+|\/connector_platform_oauth_redirect)$/.test(u.pathname))}catch{return false}
}
function escapeHtml(v){return safeString(v,1500).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function authorizeForm(req){
 const u=new URL(req.url),q=u.searchParams;
 if(q.get('response_type')!=='code'||!isChatGPTCallback(q.get('redirect_uri'))||q.get('code_challenge_method')!=='S256'||!/^[a-zA-Z0-9_-]{43,128}$/.test(q.get('code_challenge')||''))return err('Invalid authorization request');
 const params=['client_id','redirect_uri','state','code_challenge','resource'].map(k=>'<input type="hidden" name="'+k+'" value="'+escapeHtml(q.get(k)||'')+'">').join('');
 const html='<!DOCTYPE html><html lang="ru"><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Рацион+ — подтверждение</title><style>body{font:16px system-ui;background:#f6f8fa;margin:0;padding:40px 16px}.card{max-width:430px;background:white;margin:auto;padding:30px;border-radius:18px;box-shadow:0 4px 24px #ddd}input,button{box-sizing:border-box;width:100%;padding:15px;margin:12px 0;border-radius:9px;border:1px solid #ccc;font:inherit}button{background:#166534;color:white;border:0;font-weight:700}</style><div class="card"><h2>Подключить Рацион+ к ChatGPT</h2><p>Введи пароль, который ты задал в Cloudflare. Он не передаётся ChatGPT и не публикуется.</p><form method="post" action="/oauth/authorize">'+params+'<input type="password" name="password" autocomplete="off" placeholder="Пароль доступа" required><button type="submit">Разрешить публикации</button></form></div></html>';
 return new Response(html,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','X-Frame-Options':'DENY'}});
}
async function grant(req,env){
 const f=await req.formData(),password=String(f.get('password')||'');
 // Hash comparison avoids trivial character-by-character timing exposure.
 const raw=new TextEncoder(),a=new Uint8Array(await crypto.subtle.digest('SHA-256',raw.encode(password))),b=new Uint8Array(await crypto.subtle.digest('SHA-256',raw.encode(env.OWNER_PASSWORD||'')));
 let diff=a.length===b.length?0:1;for(let i=0;i<a.length;i++)diff|=(a[i]^b[i]);
 if(diff||!env.OWNER_PASSWORD||env.OWNER_PASSWORD.length<12)return new Response('Неверный пароль или сервер не настроен.',{status:403});
 const redirect_uri=String(f.get('redirect_uri')||'');
 const challenge=String(f.get('code_challenge')||'');
 if(!isChatGPTCallback(redirect_uri)||!/^[A-Za-z0-9_-]{43,128}$/.test(challenge))return err('Invalid redirect or PKCE');
 const client_id=String(f.get('client_id')||'').slice(0,500);
 const res=String(f.get('resource')||'');
 if(res&&res!==protectedResource(req))return err('Invalid resource');
 const code=await sign(env,{kind:'code',client_id,redirect_uri,challenge,res:protectedResource(req),exp:Math.floor(Date.now()/1000)+300,nonce:crypto.randomUUID()});
 const to=new URL(redirect_uri);to.searchParams.set('code',code);if(f.get('state'))to.searchParams.set('state',String(f.get('state')));to.searchParams.set('iss',site(req));
 return new Response(null,{status:302,headers:{Location:to.toString(),'cache-control':'no-store'}});
}
async function tokenEndpoint(req,env){
 const form=await req.formData(),type=String(form.get('grant_type')||''),aud=protectedResource(req);
 if(type==='refresh_token'){
  const refresh=await verify(env,String(form.get('refresh_token')||''),'refresh');if(!refresh||refresh.aud!==aud)return err('invalid_grant',400);
  return jr({access_token:await sign(env,{kind:'access',aud,scope:'telegram:publish',exp:Math.floor(Date.now()/1000)+3600}),token_type:'Bearer',expires_in:3600,scope:'telegram:publish',refresh_token:String(form.get('refresh_token'))});
 }
 if(type!=='authorization_code')return err('unsupported_grant_type',400);
 const codeString=String(form.get('code')||'');
 const c=await verify(env,codeString,'code');
 if(!c||c.res!==aud||c.client_id!==String(form.get('client_id')||'')||c.redirect_uri!==String(form.get('redirect_uri')||''))return err('invalid_grant',400);
 const verifier=String(form.get('code_verifier')||'');
 if(!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier))return err('invalid_grant',400);
 const challenge=bytesTo64(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))));
 if(challenge!==c.challenge)return err('invalid_grant',400);
 if(env.STATE){const claim='oauth:code:'+c.nonce;if(await env.STATE.get(claim))return err('invalid_grant',400);await env.STATE.put(claim,'used',{expirationTtl:600})}
 const now=Math.floor(Date.now()/1000);
 return jr({access_token:await sign(env,{kind:'access',aud,scope:'telegram:publish',exp:now+3600}),token_type:'Bearer',expires_in:3600,
  scope:'telegram:publish',refresh_token:await sign(env,{kind:'refresh',aud,scope:'telegram:publish',exp:now+60*60*24*90})});
}
const fileDef={type:'object',additionalProperties:false,properties:{
 download_url:{type:'string'},file_id:{type:'string'},mime_type:{type:'string'},file_name:{type:'string'}},
 required:['download_url','file_id']};
const pubTool={name:'publish_meal',title:'Опубликовать еду в канал Рацион+',description:'Отправить рассчитанный приём пищи в Telegram-канал @ration_sergey_post с реальными прикреплёнными изображениями из текущего чата и дневными прогресс-барами. Только когда пользователь попросил отправить/опубликовать. ChatGPT рассчитывает КБЖУ, этот инструмент НЕ вызывает платный OpenAI API. Для прикреплённых файлов передай их в поле photos. Дневные суммы накапливаются на сервере. Каждый вызов реально публикует пост.',
 inputSchema:{type:'object',additionalProperties:false,properties:{
  description:{type:'string',description:'Готовый русский текст: приём пищи, перечисление продуктов, весов и калорий/белка.'},
  calories:{type:'number',minimum:0,maximum:5000},protein:{type:'number',minimum:0,maximum:500},
  date:{type:'string',description:'YYYY-MM-DD по московскому времени (можно опустить: берётся текущая московская дата).'},
  photos:{type:'array',items:fileDef,maxItems:4,description:'Реальные фотографии пользователя, прикреплённые к беседе ChatGPT, до четырёх.'},
  require_photo:{type:'boolean',description:'True, если пользователь прислал изображение и требует публикации именно с изображением; при потере файла сервер НЕ отправит пост только с текстом.'},
  idempotency_key:{type:'string',description:'Один устойчивый UUID для этого конкретного приёма пищи; повтор того же вызова не создаст новый пост.'}
 },required:['description','calories','protein']},
 annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:true,idempotentHint:false},
 _meta:{'openai/fileParams':['photos'],'openai/toolInvocation/invoking':'Публикую приём пищи в Telegram','openai/toolInvocation/invoked':'Проверил результат публикации'},
 securitySchemes:[{type:'oauth2',scopes:['telegram:publish']}]
};
const readTool={name:'get_daily_progress',title:'Узнать прогресс за день',description:'Прочитать текущий накопленный дневной итог калорий и белка, без публикации. Можно вызвать перед расчётом новой еды.',inputSchema:{type:'object',properties:{date:{type:'string',description:'YYYY-MM-DD или пропущено для текущей московской даты'}},additionalProperties:false},annotations:{readOnlyHint:true},securitySchemes:[{type:'oauth2',scopes:['telegram:publish']}]};
const fixTool={name:'set_daily_progress',title:'Исправить дневной итог',description:'Установить ТОЧНЫЕ накопленные калории и белок за день, если нужно внести питание из прежней переписки или исправить ошибку. Не публикует сообщений.',inputSchema:{type:'object',additionalProperties:false,properties:{date:{type:'string'},calories:{type:'number',minimum:0,maximum:15000},protein:{type:'number',minimum:0,maximum:1200}},required:['calories','protein']},annotations:{readOnlyHint:false},securitySchemes:[{type:'oauth2',scopes:['telegram:publish']}]};
const validDate=date=>/^\d{4}-\d{2}-\d{2}$/.test(date);
const isTrustedHost=host=>['api.openai.com','files.oaiusercontent.com','files.openai.com','chatgpt.com'].includes(host)||host.endsWith('.oaiusercontent.com')||host.endsWith('.openai.com');
async function fetchPhoto(file){
 const u=new URL(file.download_url);
 if(u.protocol!=='https:'||!isTrustedHost(u.hostname)||u.username||u.password)throw Error('Источник изображения не относится к доверенному хосту ChatGPT');
 const r=await fetch(u,{redirect:'error',signal:AbortSignal.timeout(20000)});
 if(!r.ok)throw Error('Не удалось загрузить оригинальное изображение из ChatGPT');
 const announced=Number(r.headers.get('content-length')||0);if(announced>9_000_000)throw Error('Изображение слишком большое (>9 MB)');
 const data=await r.arrayBuffer();if(data.byteLength>9_000_000)throw Error('Изображение слишком большое (>9 MB)');
 const b=new Uint8Array(data),mime=b[0]===0xff&&b[1]===0xd8&&b[2]===0xff?'image/jpeg':
  b[0]===0x89&&b[1]===0x50&&b[2]===0x4e&&b[3]===0x47?'image/png':
  b[0]===0x52&&b[1]===0x49&&b[2]===0x46&&b[3]===0x46&&String.fromCharCode(...b.slice(8,12))==='WEBP'?'image/webp':null;
 if(!mime)throw Error('Невалидное изображение: допускаются JPEG, PNG и WebP');
 return {mime,data:new Blob([data],{type:mime})};
}
async function telegram(env,method,body){
 const url='https://api.telegram.org/bot'+env.TELEGRAM_BOT_TOKEN+'/'+method;
 const payload=body instanceof FormData?{body}:{method:'POST',body:JSON.stringify(body),headers:{'content-type':'application/json'}};
 const r=await fetch(url,{method:'POST',...payload});
 const j=await r.json().catch(()=>({}));
 if(!r.ok||!j.ok)throw Error('Ошибка Telegram: '+(j.description||r.status));
 return j.result;
}
async function publish(args,env){
 if(!env.TELEGRAM_BOT_TOKEN||!env.TELEGRAM_CHAT_ID||!env.STATE)throw Error('Сервер не настроен: секрет бота, канал или хранилище STATE отсутствуют');
 const desc=safeString(args.description,1700),cal=Number(args.calories),p=Number(args.protein);
 if(!desc||!Number.isFinite(cal)||cal<0||cal>5000||!Number.isFinite(p)||p<0||p>500)throw Error('Проверь описание, калории и белок');
 const date=args.date?String(args.date):nowDate();if(!validDate(date))throw Error('Неверная дата');
 const files=Array.isArray(args.photos)?args.photos:[];
 if(args.require_photo&&files.length===0)throw Error('Не получено прикреплённое изображение ChatGPT. Пост НЕ опубликован.');
 if(files.length>4)throw Error('Максимум четыре фотографии');
 const idem=String(args.idempotency_key||'').slice(0,100),dedupe=idem?'post:'+idem:null;
 if(dedupe){const old=await env.STATE.get(dedupe,'json');if(old)return {...old,repeated:true}}
 const images=[];for(const file of files)images.push(await fetchPhoto(file));
 const d=await day(env,date),post=renderPost({...args,description:desc},d);
 const caption=post.msg.slice(0,1024);
 let sent;
 try{
  if(images.length===0)sent=await telegram(env,'sendMessage',{chat_id:env.TELEGRAM_CHAT_ID,text:post.msg});
  else if(images.length===1){
   const f=new FormData();f.set('chat_id',env.TELEGRAM_CHAT_ID);f.set('photo',images[0].data,'meal.'+(images[0].mime==='image/png'?'png':images[0].mime==='image/webp'?'webp':'jpg'));f.set('caption',caption);
   sent=await telegram(env,'sendPhoto',f);
  }else{
   const f=new FormData();f.set('chat_id',env.TELEGRAM_CHAT_ID);
   f.set('media',JSON.stringify(images.map((img,i)=>({type:'photo',media:'attach://photo'+i,...(i===0?{caption}: {})}))));
   images.forEach((img,i)=>f.set('photo'+i,img.data,'meal'+i+'.'+(img.mime==='image/png'?'png':img.mime==='image/webp'?'webp':'jpg')));
   sent=await telegram(env,'sendMediaGroup',f);
  }
  if(images.length&&post.msg.length>1024)await telegram(env,'sendMessage',{chat_id:env.TELEGRAM_CHAT_ID,text:post.msg.slice(1024)});
 }catch(e){throw Error('Публикация не завершена: '+e.message)}
 let stored=true;
 try{await env.STATE.put(dailyKey(date),JSON.stringify(post.totals),{expirationTtl:60*60*24*120})}catch{stored=false}
 const messageId=Array.isArray(sent)?sent[0]?.message_id:sent?.message_id;
 const result={ok:true,date,message_id:messageId,url:String(env.TELEGRAM_CHAT_ID).startsWith('@')&&messageId?'https://t.me/'+String(env.TELEGRAM_CHAT_ID).slice(1)+'/'+messageId:null,photos:images.length,calories_added:round(cal),protein_added:round(p),new_totals:post.totals,goals:{calories:d.goalCal,protein:d.goalP},totals_saved:stored};
 if(stored&&dedupe)await env.STATE.put(dedupe,JSON.stringify(result),{expirationTtl:60*60*24*60});
 return result;
}
async function toolCall(req,env,data){
 const args=data.params?.arguments||{};
 if(data.params?.name==='get_daily_progress'){const date=args.date||nowDate();if(!validDate(date))return textResult('Неверная дата',true);return textResult(await day(env,date))}
 if(data.params?.name==='set_daily_progress'){
  const date=args.date||nowDate(),cal=Number(args.calories),p=Number(args.protein);
  if(!validDate(date)||!Number.isFinite(cal)||cal<0||cal>15000||!Number.isFinite(p)||p<0||p>1200)return textResult('Неверные значения',true);
  await env.STATE.put(dailyKey(date),JSON.stringify({cal:round(cal),protein:round(p),count:0}),{expirationTtl:60*60*24*120});
  return textResult({ok:true,date,calories:round(cal),protein:round(p)});
 }
 if(data.params?.name==='publish_meal'){try{return textResult(await publish(args,env))}catch(e){return textResult(e.message,true)}}
 return textResult('Неизвестный инструмент',true);
}
async function processMcp(req,env){
 let data;try{data=await req.json()}catch{return err('Invalid JSON')}
 if(!data||data.jsonrpc!=='2.0'||typeof data.method!=='string')return err('Invalid JSON-RPC');
 const id=data.id;
 if(data.method==='notifications/initialized')return new Response(null,{status:202});
 const result=(value)=>jr({jsonrpc:'2.0',id,result:value});
 if(data.method==='initialize')return result({protocolVersion:'2025-06-18',capabilities:{tools:{listChanged:false}},serverInfo:{name:'ration-telegram',version:'1.0.0'},instructions:'Чтобы опубликовать еду с фото и прогрессом в Telegram, используй publish_meal. Прикреплённые пользователем фото идут через fileParams, без повторного выбора. Не публикуй без запроса пользователя.'});
 if(data.method==='ping')return result({});
 if(data.method==='tools/list')return result({tools:[pubTool,readTool,fixTool]});
 if(data.method!=='tools/call')return jr({jsonrpc:'2.0',id,error:{code:-32601,message:'Method not found'}});
 const auth=(req.headers.get('authorization')||'').match(/^Bearer\s+(.+)$/i);
 const token=auth?await verify(env,auth[1],'access'):null;
 if(!token||token.aud!==protectedResource(req)||token.scope!=='telegram:publish')return jr({error:'not_authenticated'},401,{'WWW-Authenticate':'Bearer resource_metadata="'+site(req)+'/.well-known/oauth-protected-resource"'});
 return result(await toolCall(req,env,data));
}
export default {async fetch(req,env){
 try{
  const u=new URL(req.url),path=u.pathname;
  if(req.method==='OPTIONS')return new Response(null,{status:204,headers:commonHeaders(req)});
  if(path==='/.well-known/oauth-protected-resource'&&req.method==='GET')return jr({resource:protectedResource(req),authorization_servers:[site(req)],scopes_supported:['telegram:publish']});
  if(path==='/.well-known/oauth-authorization-server'&&req.method==='GET')return jr(metaAuth(req));
  if(path==='/oauth/register'&&req.method==='POST'){
   const data=await req.json().catch(()=>({}));const redirects=data.redirect_uris||[];
   if(!Array.isArray(redirects)||!redirects.length||!redirects.every(isChatGPTCallback))return err('Invalid redirect URIs');
   return jr({client_id:'ration-chatgpt-'+crypto.randomUUID(),client_id_issued_at:Math.floor(Date.now()/1000),redirect_uris:redirects,grant_types:['authorization_code','refresh_token'],response_types:['code'],token_endpoint_auth_method:'none'},201);
  }
  if(path==='/oauth/authorize'&&req.method==='GET')return authorizeForm(req);
  if(path==='/oauth/authorize'&&req.method==='POST')return await grant(req,env);
  if(path==='/oauth/token'&&req.method==='POST')return await tokenEndpoint(req,env);
  if(path==='/health'&&req.method==='GET')return jr({ready:!!(env.TELEGRAM_BOT_TOKEN&&env.OWNER_PASSWORD&&env.TELEGRAM_CHAT_ID&&env.STATE),service:'Рацион+ Telegram publisher'});
  if(path==='/mcp'&&req.method==='POST')return await processMcp(req,env);
  if(path==='/mcp')return new Response('Method Not Allowed',{status:405,headers:{Allow:'POST'}});
  return err('Not found',404);
 }catch(e){return err('Server error',500)}
}};
export {renderPost,bar};
