/**
 * api/discord.js · HUMOS420 Community · intermediario con Discord
 * VERSIÓN: 2026-11-04 v1
 *
 * Para qué está: Discord bloquea los pedidos que salen de los servidores de Google (Apps Script). La app le pide
 * las cosas a este archivo (en Vercel) y este se las pide a Discord.
 *
 * Seguridad:
 * - Solo atiende a la app: cada pedido tiene que traer la clave PUENTE_CLAVE en el encabezado X-Puente-Clave.
 * - El token del bot y el Client Secret viven SOLO acá (variables de entorno de Vercel), nunca en Apps Script.
 * - Solo deja pasar las operaciones que usa la app (lista de abajo), y solo sobre el servidor DISCORD_SERVIDOR_ID.
 *
 * Variables de entorno (Vercel → Settings → Environment Variables):
 *   PUENTE_CLAVE           la misma clave larga que se carga en Apps Script como DISCORD_PUENTE_CLAVE
 *   DISCORD_BOT_TOKEN      pestaña Bot del portal de Discord
 *   DISCORD_CLIENT_SECRET  pestaña OAuth2 del portal de Discord
 *   DISCORD_SERVIDOR_ID    ID del servidor de HUMOS420
 */

const crypto = require('crypto');

const API = 'https://discord.com/api/v10';
const UA = 'DiscordBot (https://humos420community.vercel.app, 1.0)';
const N = '\\d{5,25}';   // un ID de Discord

// Lo único que deja pasar. auth: 'bot' = con el token del bot · 'bearer' = con el permiso del usuario · null = sin.
// secreto: true = le agrega el Client Secret (pasos de OAuth). servidor: true = el ID del servidor tiene que ser el nuestro.
const PERMITIDOS = [
  { metodo: 'post', re: /^\/oauth2\/token$/, auth: [null], secreto: true },
  { metodo: 'post', re: /^\/oauth2\/token\/revoke$/, auth: [null], secreto: true },
  { metodo: 'get', re: /^\/users\/@me$/, auth: ['bot', 'bearer'] },
  { metodo: 'get', re: /^\/users\/@me\/guilds$/, auth: ['bot'] },
  { metodo: 'get', re: new RegExp('^/guilds/(' + N + ')$'), auth: ['bot'], servidor: true },
  { metodo: 'get', re: new RegExp('^/guilds/(' + N + ')/members/' + N + '$'), auth: ['bot'], servidor: true },
  { metodo: 'put', re: new RegExp('^/guilds/(' + N + ')/members/' + N + '$'), auth: ['bot'], servidor: true },
  { metodo: 'put', re: new RegExp('^/guilds/(' + N + ')/members/' + N + '/roles/' + N + '$'), auth: ['bot'], servidor: true }
];

function igual(a, b) {
  const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || ''));
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}

function responder(res, estado, cuerpo) {
  res.setHeader('Cache-Control', 'no-store');
  res.status(estado).json(Object.assign({ puente: true }, cuerpo));
}

module.exports = async function (req, res) {
  const env = process.env;
  if (req.method === 'GET') return responder(res, 200, { ok: true, version: 'v1' });   // para ver que está publicado
  if (req.method !== 'POST') return responder(res, 405, { error: 'Método no permitido' });

  const faltan = ['PUENTE_CLAVE', 'DISCORD_BOT_TOKEN', 'DISCORD_CLIENT_SECRET', 'DISCORD_SERVIDOR_ID'].filter(function (k) { return !env[k]; });
  if (faltan.length) return responder(res, 500, { error: 'Faltan variables de entorno en Vercel: ' + faltan.join(', ') });
  if (!igual(req.headers['x-puente-clave'], env.PUENTE_CLAVE)) return responder(res, 401, { error: 'Clave del puente incorrecta' });

  let p = req.body;
  if (typeof p === 'string') { try { p = JSON.parse(p); } catch (e) { p = null; } }
  if (!p || typeof p !== 'object') return responder(res, 400, { error: 'Pedido vacío' });

  const metodo = String(p.metodo || '').toLowerCase(), ruta = String(p.ruta || ''), auth = p.auth || null;
  const regla = PERMITIDOS.filter(function (r) { return r.metodo === metodo && r.re.test(ruta); })[0];
  if (!regla) return responder(res, 403, { error: 'Operación no permitida: ' + metodo + ' ' + ruta.slice(0, 80) });
  const tipoAuth = auth === 'bot' ? 'bot' : (typeof auth === 'string' && /^Bearer [\w.-]{10,200}$/.test(auth) ? 'bearer' : null);
  if (regla.auth.indexOf(tipoAuth) === -1) return responder(res, 403, { error: 'Autorización no permitida para esa operación' });
  if (regla.servidor && regla.re.exec(ruta)[1] !== String(env.DISCORD_SERVIDOR_ID).trim()) return responder(res, 403, { error: 'Ese no es el servidor de la app' });

  const op = { method: metodo.toUpperCase(), headers: { 'User-Agent': UA } };
  if (tipoAuth === 'bot') op.headers.Authorization = 'Bot ' + String(env.DISCORD_BOT_TOKEN).trim();
  if (tipoAuth === 'bearer') op.headers.Authorization = auth;
  const datos = p.datos && typeof p.datos === 'object' ? Object.assign({}, p.datos) : null;
  if (regla.secreto) {
    if (!datos) return responder(res, 400, { error: 'Faltan datos' });
    datos.client_secret = String(env.DISCORD_CLIENT_SECRET).trim();
    op.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    op.body = new URLSearchParams(datos).toString();
  } else if (datos) {
    op.headers['Content-Type'] = 'application/json';
    op.body = JSON.stringify(datos);
  } else if (metodo === 'put' || metodo === 'post') {
    op.headers['Content-Length'] = '0';
  }

  try {
    const r = await fetch(API + ruta, op);
    const texto = await r.text();
    return responder(res, 200, { codigo: r.status, texto: texto.slice(0, 20000) });
  } catch (e) {
    return responder(res, 200, { codigo: 0, texto: 'Vercel no pudo conectar con Discord: ' + (e && e.message ? e.message : e) });
  }
};
