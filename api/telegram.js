/**
 * api/telegram.js · HUMOS420 Community · intermediario entre Telegram y la app
 * VERSIÓN: 2026-11-05 v1
 *
 * Para qué está: Telegram le avisa acá de cada mensaje al bot y de cada pedido para entrar al grupo. Esto se lo pasa
 * a la app de Apps Script (doPost en Telegram.gs), y lo que la app contesta (por ejemplo, un mensaje o aceptar a
 * alguien en el grupo) se le devuelve a Telegram, que lo ejecuta.
 * (No se conecta Telegram directo con Apps Script porque Apps Script responde con una redirección y Telegram
 * lo toma como error y repite los mensajes.)
 *
 * Seguridad: solo atiende pedidos con la clave PUENTE_CLAVE en el encabezado X-Telegram-Bot-Api-Secret-Token
 * (Telegram la manda sola: se la da configurarTelegram). El token del bot no pasa por acá.
 *
 * Variables de entorno (Vercel → Settings → Environments → Production → Environment Variables):
 *   PUENTE_CLAVE    la misma clave que usa la app (ya estaba cargada)
 *   APPS_SCRIPT_URL la dirección …/exec de la implementación que abre la página (index.html → APP_URL)
 */

const crypto = require('crypto');

function igual(a, b) {
  const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || ''));
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}

module.exports = async function (req, res) {
  const env = process.env;
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET') return res.status(200).json({ ok: true, puente: 'telegram', version: 'v1', configurado: !!(env.PUENTE_CLAVE && env.APPS_SCRIPT_URL) });
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Método no permitido' });
  if (!env.PUENTE_CLAVE || !env.APPS_SCRIPT_URL) return res.status(500).json({ ok: false, error: 'Faltan PUENTE_CLAVE o APPS_SCRIPT_URL en las variables de entorno de Vercel' });
  if (!igual(req.headers['x-telegram-bot-api-secret-token'], env.PUENTE_CLAVE)) return res.status(401).json({ ok: false, error: 'Clave incorrecta' });

  let update = req.body;
  if (typeof update === 'string') { try { update = JSON.parse(update); } catch (e) { update = null; } }
  if (!update || typeof update !== 'object') return res.status(200).json({});

  try {
    // Apps Script responde con una redirección: fetch la sigue sola y trae la respuesta de doPost.
    const r = await fetch(String(env.APPS_SCRIPT_URL).trim(), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clave: env.PUENTE_CLAVE, update: update }), redirect: 'follow'
    });
    const texto = await r.text();
    let j = null;
    try { j = JSON.parse(texto); } catch (e) { j = null; }
    if (!j || !j.ok) {
      console.error('La app respondió ' + r.status + ': ' + texto.slice(0, 300));
      return res.status(200).json({ error_apps_script: true, estado: r.status });   // 200: así Telegram no repite el mensaje
    }
    return res.status(200).json(j.respuesta || {});
  } catch (e) {
    console.error('No pude hablar con la app: ' + (e && e.message ? e.message : e));
    return res.status(200).json({ error_apps_script: true });
  }
};
