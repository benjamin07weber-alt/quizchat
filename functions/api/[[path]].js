// Quizchat diagnostic API v1.1. Temporary debugging build.
const json = (data, status = 200) => new Response(JSON.stringify(data), {status, headers: {'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
const hex = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2,'0')).join('');
const sha = async s => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
const hashPassword = async (password, salt) => {
  const key = await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);
  return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:210000,hash:'SHA-256'},key,256));
};
const rand = () => hex(crypto.getRandomValues(new Uint8Array(32)));
async function current(request,db) {
  const token = (request.headers.get('Authorization') || '').replace(/^Bearer /,'');
  if (!token) return null;
  return db.prepare('SELECT users.id,users.nickname FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?').bind(await sha(token),Date.now()).first();
}
export async function onRequest({request,env,params}) {
  const db = env.DB;
  if (!db) return json({error:'Cloudflare D1 binding DB is missing',stage:'binding'},503);
  const route = (params.path || []).join('/');
  const method = request.method;
  let stage = 'start';
  try {
    if (route === 'auth' && method === 'POST') {
      stage = 'read auth request';
      const {mode,nickname,password} = await request.json();
      if (typeof nickname !== 'string' || !/^[a-zA-Z0-9_]{3,20}$/.test(nickname) || typeof password !== 'string' || password.length < 8 || password.length > 128)
        return json({error:'Use a 3–20 character nickname and an 8+ character password'},400);
      let user;
      if (mode === 'register') {
        stage = 'generate salt';
        const salt = rand();
        stage = 'hash password';
        const passwordHash = await hashPassword(password,salt);
        stage = 'insert user';
        try {
          await db.prepare('INSERT INTO users(nickname,salt,password_hash) VALUES(?,?,?)').bind(nickname,salt,passwordHash).run();
        } catch (e) {
          console.error('Quizchat registration INSERT failed:', e);
          if (/UNIQUE constraint failed/i.test(String(e?.message || e))) return json({error:'That nickname is already taken!'},409);
          throw e;
        }
        stage = 'read registered user';
        user = await db.prepare('SELECT id,nickname FROM users WHERE nickname=?').bind(nickname).first();
      } else if (mode === 'login') {
        stage = 'read login user';
        user = await db.prepare('SELECT * FROM users WHERE nickname=?').bind(nickname).first();
        stage = 'verify password';
        if (!user || await hashPassword(password,user.salt) !== user.password_hash) return json({error:'Incorrect nickname or password'},401);
      } else return json({error:'Invalid mode'},400);
      if (!user) throw new Error('Account not found after registration');
      stage = 'create session token';
      const token = rand();
      stage = 'insert session';
      await db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await sha(token),user.id,Date.now()+30*86400000).run();
      return json({token,nickname:user.nickname});
    }
    stage = 'verify session';
    const me = await current(request,db);
    if (!me) return json({error:'Unauthorized'},401);
    if (route === 'logout' && method === 'POST') {
      stage = 'logout';
      const token = (request.headers.get('Authorization') || '').replace(/^Bearer /,'');
      await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(token)).run();
      return json({ok:true});
    }
    if (route === 'users' && method === 'GET') {
      stage = 'search users';
      const q = (new URL(request.url).searchParams.get('q') || '').slice(0,20);
      const result = await db.prepare('SELECT nickname FROM users WHERE nickname LIKE ? AND id != ? ORDER BY nickname LIMIT 100').bind('%'+q.replace(/[%_]/g,'\\$&')+'%',me.id).all();
      return json({users:result.results});
    }
    if (route === 'messages' && method === 'GET') {
      stage = 'read messages query';
      const url = new URL(request.url), peer = url.searchParams.get('with'), after = Number(url.searchParams.get('after') || 0);
      if (!peer || !Number.isSafeInteger(after) || after < 0) return json({error:'Invalid chat'},400);
      stage = 'find chat peer';
      const other = await db.prepare('SELECT id FROM users WHERE nickname=?').bind(peer).first();
      if (!other) return json({error:'User not found'},404);
      stage = 'load messages';
      const r = await db.prepare('SELECT m.id,u.nickname sender,m.body,m.created_at FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id>? AND ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)) ORDER BY m.id LIMIT 200').bind(after,me.id,other.id,other.id,me.id).all();
      return json({messages:r.results});
    }
    if (route === 'messages' && method === 'POST') {
      stage = 'read message request';
      const {to,body} = await request.json();
      if (typeof to !== 'string' || typeof body !== 'string' || !body.trim() || body.length > 2000) return json({error:'Invalid message'},400);
      stage = 'find message recipient';
      const other = await db.prepare('SELECT id FROM users WHERE nickname=?').bind(to).first();
      if (!other || other.id === me.id) return json({error:'Recipient not found'},404);
      stage = 'insert message';
      await db.prepare('INSERT INTO messages(sender_id,receiver_id,body) VALUES(?,?,?)').bind(me.id,other.id,body.trim()).run();
      return json({ok:true});
    }
    return json({error:'Not found'},404);
  } catch(e) {
    const detail = String(e?.message || e).slice(0,350);
    console.error('QUIZCHAT API FAILURE', {route,method,stage,detail,stack:e?.stack});
    // Temporary diagnostics: do not leave internal DB error details public after fixing.
    return json({error:'Server error',stage,detail},500);
  }
}
