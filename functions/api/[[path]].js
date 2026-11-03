const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
const hex=buf=>[...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,'0')).join('');
const sha=async s=>hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));
const hashPassword=async(password,salt)=>{const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:100000,hash:'SHA-256'},key,256))};
const rand=()=>hex(crypto.getRandomValues(new Uint8Array(32)).buffer);
async function current(request,db){const token=(request.headers.get('Authorization')||'').replace(/^Bearer /,'');if(!token)return null;return db.prepare('SELECT users.id,users.nickname FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?').bind(await sha(token),Date.now()).first()}
export async function onRequest({request,env,params}){
 const db=env.DB;
 if(!db)return json({error:'Database connection missing'},503);
 const route=(params.path||[]).join('/');const method=request.method;let stage='starting';
 try{
  if(route==='auth'&&method==='POST'){
   stage='reading account details';const {mode,nickname,password}=await request.json();
   if(typeof nickname!=='string'||!/^[a-zA-Z0-9_]{3,20}$/.test(nickname)||typeof password!=='string'||password.length<8||password.length>128)return json({error:'Use a 3–20 character nickname and an 8+ character password'},400);
   let user;
   if(mode==='register'){
    stage='generating password salt';const salt=rand();stage='hashing password';const passwordHash=await hashPassword(password,salt);
    stage='checking nickname';const existing=await db.prepare('SELECT id FROM users WHERE nickname=? COLLATE NOCASE').bind(nickname).first();if(existing)return json({error:'That nickname is already taken!'},409);
    stage='creating account';
    try{await db.prepare('INSERT INTO users(nickname,salt,password_hash) VALUES(?,?,?)').bind(nickname,salt,passwordHash).run()}
    catch(e){console.error('Registration insert failed:',e);const duplicate=await db.prepare('SELECT id FROM users WHERE nickname=? COLLATE NOCASE').bind(nickname).first();if(duplicate)return json({error:'That nickname is already taken!'},409);throw e}
    stage='loading new account';user=await db.prepare('SELECT id,nickname FROM users WHERE nickname=?').bind(nickname).first();
   }else if(mode==='login'){
    stage='finding account';user=await db.prepare('SELECT * FROM users WHERE nickname=? COLLATE NOCASE').bind(nickname).first();stage='checking password';
    if(!user||await hashPassword(password,user.salt)!==user.password_hash)return json({error:'Incorrect nickname or password'},401);
   }else return json({error:'Invalid mode'},400);
   if(!user)throw new Error('Account could not be loaded');
   stage='creating session';const token=rand();await db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await sha(token),user.id,Date.now()+30*86400000).run();return json({token,nickname:user.nickname});
  }
  stage='checking login session';const me=await current(request,db);if(!me)return json({error:'Unauthorized'},401);
  if(route==='logout'&&method==='POST'){stage='logging out';const token=(request.headers.get('Authorization')||'').replace(/^Bearer /,'');await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(token)).run();return json({ok:true})}
  if(route==='users'&&method==='GET'){stage='searching users';const q=(new URL(request.url).searchParams.get('q')||'').slice(0,20);const result=await db.prepare('SELECT nickname FROM users WHERE nickname LIKE ? AND id != ? ORDER BY nickname LIMIT 100').bind('%'+q.replace(/[%_\\]/g,'\\$&')+'%',me.id).all();return json({users:result.results})}
  if(route==='messages'&&method==='GET'){stage='loading messages';const url=new URL(request.url),peer=url.searchParams.get('with'),after=Number(url.searchParams.get('after')||0);if(!peer||!Number.isSafeInteger(after)||after<0)return json({error:'Invalid chat'},400);const other=await db.prepare('SELECT id FROM users WHERE nickname=? COLLATE NOCASE').bind(peer).first();if(!other)return json({error:'User not found'},404);const result=await db.prepare('SELECT m.id,u.nickname sender,m.body,m.created_at FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id>? AND ((m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)) ORDER BY m.id LIMIT 200').bind(after,me.id,other.id,other.id,me.id).all();return json({messages:result.results})}
  if(route==='messages'&&method==='POST'){stage='sending message';const {to,body}=await request.json();if(typeof to!=='string'||typeof body!=='string'||!body.trim()||body.length>2000)return json({error:'Invalid message'},400);const other=await db.prepare('SELECT id FROM users WHERE nickname=? COLLATE NOCASE').bind(to).first();if(!other||other.id===me.id)return json({error:'Recipient not found'},404);await db.prepare('INSERT INTO messages(sender_id,receiver_id,body) VALUES(?,?,?)').bind(me.id,other.id,body.trim()).run();return json({ok:true})}
  return json({error:'Not found'},404);
 }catch(e){console.error('QUIZCHAT API ERROR',{stage,message:e?.message,stack:e?.stack});return json({error:'Server error',stage,debug:'Check Cloudflare Functions logs'},500)}
}
