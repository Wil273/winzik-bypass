export async function onRequestPost({ request, env }) {
  try {
    if (!env.KEYS) return Response.json({valid:false,message:"Servidor ainda não configurado: falta o KV KEYS."},{status:503});
    const body = await request.json(); const key = String(body.key || "").trim();
    if (!key || key.length > 120) return Response.json({valid:false,message:"Digite uma key válida."},{status:400});
    const raw = await env.KEYS.get("key:" + key); if (!raw) return Response.json({valid:false,message:"Key inválida ou expirada."},{status:401});
    const record = JSON.parse(raw); if (record.revoked || !record.expiresAt || Date.now() >= record.expiresAt) return Response.json({valid:false,message:"Key revogada ou expirada."},{status:401});
    return Response.json({valid:true,expiresAt:record.expiresAt});
  } catch { return Response.json({valid:false,message:"Erro ao validar key."},{status:400}); }
}
