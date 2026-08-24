
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET to a random secret of at least 32 characters.");
  process.exit(1);
}

const app = express();
const db = new Database(process.env.DB_PATH || "mergecoin.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 referral_code TEXT UNIQUE NOT NULL,
 referred_by TEXT,
 referral_count INTEGER NOT NULL DEFAULT 0,
 coins INTEGER NOT NULL DEFAULT 50,
 energy INTEGER NOT NULL DEFAULT 20,
 level INTEGER NOT NULL DEFAULT 1,
 xp INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 last_daily TEXT,
 FOREIGN KEY(referred_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS referrals (
 inviter_id TEXT NOT NULL,
 invitee_id TEXT PRIMARY KEY,
 created_at TEXT NOT NULL,
 FOREIGN KEY(inviter_id) REFERENCES users(id),
 FOREIGN KEY(invitee_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 type TEXT NOT NULL,
 amount INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
`);

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"20kb"}));
app.use(rateLimit({windowMs:60_000,max:120,standardHeaders:true,legacyHeaders:false}));
app.use(express.static(path.join(__dirname,"public")));

const findUserById=db.prepare("SELECT * FROM users WHERE id=?");
const findUserByName=db.prepare("SELECT * FROM users WHERE username=?");
const findUserByCode=db.prepare("SELECT * FROM users WHERE referral_code=?");
const insertUser=db.prepare(`INSERT INTO users
(id,username,password_hash,referral_code,referred_by,coins,energy,created_at)
VALUES (?,?,?,?,?,?,?,?)`);
const insertReferral=db.prepare("INSERT INTO referrals(inviter_id,invitee_id,created_at) VALUES (?,?,?)");
const addInviter=db.prepare("UPDATE users SET referral_count=referral_count+1,coins=coins+100 WHERE id=?");
const addEvent=db.prepare("INSERT INTO events(id,user_id,type,amount,created_at) VALUES (?,?,?,?,?)");

function now(){return new Date().toISOString();}
function makeCode(){return crypto.randomBytes(5).toString("hex").toUpperCase();}
function publicUser(u){return {
 id:u.id,username:u.username,referralCode:u.referral_code,referredBy:u.referred_by,
 referralCount:u.referral_count,coins:u.coins,energy:u.energy,level:u.level,xp:u.xp,lastDaily:u.last_daily
};}
function tokenFor(u){return jwt.sign({sub:u.id},JWT_SECRET,{expiresIn:"7d"});}
function auth(req,res,next){
 const h=req.headers.authorization||"";
 const token=h.startsWith("Bearer ")?h.slice(7):null;
 if(!token)return res.status(401).json({error:"กรุณาเข้าสู่ระบบ"});
 try{
   const p=jwt.verify(token,JWT_SECRET),u=findUserById.get(p.sub);
   if(!u)return res.status(401).json({error:"เซสชันไม่ถูกต้อง"});
   req.user=u;next();
 }catch{res.status(401).json({error:"เซสชันหมดอายุ"});}
}
function validUsername(s){return /^[a-zA-Z0-9_]{3,24}$/.test(s);}
function validPassword(s){return typeof s==="string" && s.length>=8 && s.length<=128;}

const registerTx=db.transaction(({username,password,ref})=>{
 let inviter=null;
 if(ref){inviter=findUserByCode.get(ref);if(!inviter)throw new Error("ไม่พบรหัสเชิญ");}
 if(findUserByName.get(username))throw new Error("ชื่อผู้ใช้นี้ถูกใช้แล้ว");
 let code;do{code=makeCode()}while(findUserByCode.get(code));
 const id=crypto.randomUUID(), t=now(), initial=inviter?100:50;
 const hash=bcrypt.hashSync(password,12);
 insertUser.run(id,username,hash,code,inviter?inviter.id:null,initial,20,t);
 if(inviter){
   insertReferral.run(inviter.id,id,t);
   addInviter.run(inviter.id);
   addEvent.run(crypto.randomUUID(),inviter.id,"referral_bonus",100,t);
   addEvent.run(crypto.randomUUID(),id,"welcome_referral_bonus",50,t);
 }
 addEvent.run(crypto.randomUUID(),id,"welcome",initial,t);
 return findUserById.get(id);
});

app.post("/api/register",(req,res)=>{
 try{
   let {username,password,referredBy=""}=req.body||{};
   username=String(username||"").trim();
   referredBy=String(referredBy||"").trim().toUpperCase();
   if(!validUsername(username))return res.status(400).json({error:"ชื่อผู้ใช้ 3-24 ตัว ใช้ A-Z, 0-9, _"});
   if(!validPassword(password))return res.status(400).json({error:"รหัสผ่านต้องยาวอย่างน้อย 8 ตัว"});
   if(referredBy && !/^[A-F0-9]{10}$/.test(referredBy))return res.status(400).json({error:"รหัสเชิญไม่ถูกต้อง"});
   const u=registerTx({username,password,ref:referredBy});
   res.json({token:tokenFor(u),user:publicUser(u)});
 }catch(e){res.status(400).json({error:e.message||"สมัครไม่สำเร็จ"});}
});

app.post("/api/login",(req,res)=>{
 const username=String(req.body?.username||"").trim();
 const password=String(req.body?.password||"");
 const u=findUserByName.get(username);
 if(!u || !bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:"ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"});
 res.json({token:tokenFor(u),user:publicUser(u)});
});

app.get("/api/me",auth,(req,res)=>res.json(publicUser(findUserById.get(req.user.id))));

app.post("/api/daily",auth,(req,res)=>{
 const u=findUserById.get(req.user.id), today=new Date().toISOString().slice(0,10);
 if(u.last_daily===today)return res.status(409).json({error:"รับ Daily Reward วันนี้แล้ว",user:publicUser(u)});
 db.prepare("UPDATE users SET last_daily=?,energy=energy+10,coins=coins+50 WHERE id=?").run(today,u.id);
 addEvent.run(crypto.randomUUID(),u.id,"daily_reward",50,now());
 res.json(publicUser(findUserById.get(u.id)));
});

app.post("/api/game/spawn",auth,(req,res)=>{
 const u=findUserById.get(req.user.id);
 if(u.energy<1)return res.status(409).json({error:"พลังงานหมด",user:publicUser(u)});
 db.prepare("UPDATE users SET energy=energy-1,xp=xp+2 WHERE id=?").run(u.id);
 addEvent.run(crypto.randomUUID(),u.id,"spawn",-1,now());
 res.json(publicUser(findUserById.get(u.id)));
});

app.post("/api/game/merge",auth,(req,res)=>{
 const amount=Math.max(1,Math.min(20,Number(req.body?.level)||1));
 const u=findUserById.get(req.user.id);
 const xp=amount*8, coins=amount*10;
 let newXp=u.xp+xp,newLevel=u.level,newEnergy=u.energy;
 while(newXp >= 100+(newLevel-1)*50){newXp-=100+(newLevel-1)*50;newLevel++;newEnergy+=3;}
 db.prepare("UPDATE users SET coins=coins+?,xp=?,level=?,energy=? WHERE id=?").run(coins,newXp,newLevel,newEnergy,u.id);
 addEvent.run(crypto.randomUUID(),u.id,"merge",coins,now());
 res.json(publicUser(findUserById.get(u.id)));
});

app.get("/api/leaderboard",(req,res)=>{
 res.json(db.prepare("SELECT username,referral_code,coins,level,referral_count FROM users ORDER BY coins DESC, level DESC LIMIT 50").all());
});
app.get("/api/health",(req,res)=>res.json({ok:true,users:db.prepare("SELECT COUNT(*) n FROM users").get().n}));

app.get("*",(req,res)=>{
 if(req.path.startsWith("/api/")) return res.status(404).json({error:"Not found"});
 res.sendFile(path.join(__dirname,"public","index.html"));
});
app.listen(PORT,()=>console.log(`Merge Coin ready on port ${PORT}`));
