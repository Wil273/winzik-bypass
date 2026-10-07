function json(data,status=200){return Response.json(data,{status,headers:{"Cache-Control":"no-store"}})}
function makeKey(){const bytes=new Uint8Array(18);crypto.getRandomValues(bytes);return "WZ-"+[...bytes].map(b=>b.toString(16).padStart(2,"0")).join("").toUpperCase()}
export async function onRequestPost({request,env}){
 try{if(!env.KEYS)return json({message:"Configure o KV binding KEYS no Cloudflare."},503);if(!env.ADMIN_PASSWORD)return json({message:"Configure a variável secreta ADMIN_PASSWORD no Cloudflare."},503);const b=await request.json();if(typeof b.password!=="string"||b.password!==env.ADMIN_PASSWORD)return json({message:"Senha de administrador incorreta."},401);
 const action=String(b.action||"");
 if(action==="create"){const hours=Number(b.hours);if(![1,24,168,720].includes(hours))return json({message:"Validade não permitida."},400);let key;do{key=makeKey()}while(await env.KEYS.get("key:"+key));const rec={key,createdAt:Date.now(),expiresAt:Date.now()+hours*3600000,revoked:false};await env.KEYS.put("key:"+key,JSON.stringify(rec));return json({key,expiresAt:rec.expiresAt})}
 if(action==="list"){let cursor,keys=[];do{const page=await env.KEYS.list({prefix:"key:",cursor,limit:100});for(const k of page.keys){const raw=await env.KEYS.get(k.name);if(raw){try{keys.push(JSON.parse(raw))}catch{}}}cursor=page.list_complete?undefined:page.cursor;}while(cursor);keys.sort((a,b)=>b.createdAt-a.createdAt);return json({keys})}
 if(action==="revoke"){const key=String(b.key||"").trim();const raw=await env.KEYS.get("key:"+key);if(!raw)return json({message:"Key não encontrada."},404);const rec=JSON.parse(raw);rec.revoked=true;rec.revokedAt=Date.now();await env.KEYS.put("key:"+key,JSON.stringify(rec));return json({revoked:true})}
 return json({message:"Ação desconhecida."},400);
 }catch{return json({message:"Erro interno na área admin."},500)}
}
