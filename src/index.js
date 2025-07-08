import { Router } from 'worktop';
import { reply } from 'worktop/utils';
import * as CORS from 'worktop/cors';
import bcrypt from 'bcryptjs';

const API = new Router();

// Registro de usuario
API.add('POST', '/register', async (req, res) => {
  const { username, password } = await req.body.json();

  if (!username || !password) {
    return reply(res, 400, { error: 'Username and password required' });
  }

  const hashed = await bcrypt.hash(password, 10);

  try {
    await req.ctx.env.DB.prepare(
      'INSERT INTO users (username, password) VALUES (?, ?)'
    ).bind(username, hashed).run();

    reply(res, 200, { message: 'User registered successfully' });
  } catch {
    reply(res, 400, { error: 'Username already exists' });
  }
});

// Inicio de sesión
API.add('POST', '/login', async (req, res) => {
  const { username, password } = await req.body.json();

  const user = await req.ctx.env.DB.prepare(
    'SELECT * FROM users WHERE username = ?'
  ).bind(username).first();

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return reply(res, 401, { error: 'Invalid username or password' });
  }

  const session = crypto.randomUUID();
  await req.ctx.env.SESSIONS.put(session, username, { expirationTtl: 3600 });

  reply(res, 200, { message: 'Login successful', session });
});

// Verificar sesión
API.add('GET', '/session', async (req, res) => {
  const url = new URL(req.url);
  const token = url.searchParams.get('token');

  if (!token) return reply(res, 400, { error: 'Missing session token' });

  const username = await req.ctx.env.SESSIONS.get(token);
  if (!username) return reply(res, 404, { error: 'Session not found or expired' });

  reply(res, 200, { username });
});

// Cloudflare Worker handler con CORS
export default {
  async fetch(request, env, ctx) {
    const handler = API.run(request, { env, ctx });
    return CORS.preflight(request, handler, {
      origins: ['*'],
      methods: ['GET', 'POST'],
      headers: ['Content-Type'],
    });
  },
};
  
