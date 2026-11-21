require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === "production";
const sessionSecret = process.env.SESSION_SECRET || "";
if (isProd && sessionSecret.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters in production.");
}
if (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
  console.warn("Set ADMIN_PASSWORD (12+ chars) in .env before production use.");
}

const db = new Database(path.join(__dirname, "data", "rudy.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 disabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS campaigns (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 category TEXT NOT NULL,
 description TEXT NOT NULL,
 requirements TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS claims (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
 player_uid TEXT NOT NULL,
 details TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 admin_note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TEXT
);
`);
const count = db.prepare("SELECT COUNT(*) n FROM campaigns").get().n;
if (!count) {
  const add = db.prepare("INSERT INTO campaigns(title,category,description,requirements) VALUES(?,?,?,?)");
  add.run("Community Challenge","ACTIVITY CAMPAIGN","Join a community activity and submit a description for review.","Describe the activity you completed. Do not submit passwords or one-time codes.");
  add.run("Creator Spotlight","COMMUNITY EVENT","Participate in an eligible community creator event.","Provide the event name and a brief description of your participation.");
  add.run("Verified Giveaway","PROMOTIONAL DRAW","Enter an eligible promotional draw, subject to published rules.","Include the public giveaway reference and confirm that you meet its eligibility rules.");
}

app.disable("x-powered-by");
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"20kb"}));
app.use(express.urlencoded({extended:false,limit:"20kb"}));
app.use(session({
  store:new SQLiteStore({db:"sessions.sqlite",dir:path.join(__dirname,"data")}),
  secret:sessionSecret || "development-only-change-this-session-secret",
  resave:false,saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"strict",secure:isProd,maxAge:1000*60*60*8}
}));
app.use(express.static(path.join(__dirname,"public")));

const authLimiter = rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:true,legacyHeaders:false,message:{error:"Too many attempts. Try again later."}});
const clean = (v,max=500)=>typeof v==="string"?v.trim().slice(0,max):"";
const fail = (res,status,error)=>res.status(status).json({error});
function requireAuth(req,res,next){
  if(!req.session.user) return fail(res,401,"Please sign in.");
  const u=db.prepare("SELECT id,username,email,role,disabled FROM users WHERE id=?").get(req.session.user.id);
  if(!u || u.disabled){req.session.destroy(()=>{});return fail(res,401,"Account unavailable.");}
  req.session.user=u; next();
}
function requireAdmin(req,res,next){requireAuth(req,res,()=>req.session.user.role==="admin"?next():fail(res,403,"Administrator access required."));}
function csrf(req,res,next){
  if(["GET","HEAD","OPTIONS"].includes(req.method)) return next();
  const token=clean(req.get("x-csrf-token"),128);
  if(!req.session.csrf || token!==req.session.csrf) return fail(res,403,"Security token expired. Refresh and try again.");
  next();
}
app.use("/api",csrf);
app.get("/api/csrf",(req,res)=>{req.session.csrf=require("crypto").randomBytes(24).toString("hex");res.json({token:req.session.csrf});});
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));

app.post("/api/register",authLimiter,async(req,res)=>{
  const username=clean(req.body.username,24),email=clean(req.body.email,120).toLowerCase(),password=String(req.body.password||"");
  if(!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return fail(res,400,"Username must be 3–24 letters, numbers or underscores.");
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res,400,"Enter a valid email address.");
  if(password.length<12 || password.length>128) return fail(res,400,"Password must be 12–128 characters.");
  try{
    const hash=await bcrypt.hash(password,12);
    const info=db.prepare("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)").run(username,email,hash);
    req.session.regenerate(err=>{if(err)return fail(res,500,"Could not start session.");req.session.user={id:Number(info.lastInsertRowid),username,email,role:"user"};req.session.csrf=require("crypto").randomBytes(24).toString("hex");res.json({ok:true,user:req.session.user,csrf:req.session.csrf});});
  }catch(e){return fail(res,409,"Username or email is already registered.");}
});
app.post("/api/login",authLimiter,async(req,res)=>{
  const identity=clean(req.body.identity,120),password=String(req.body.password||"");
  const u=db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE").get(identity,identity);
  if(!u || u.disabled || !(await bcrypt.compare(password,u.password_hash))) return fail(res,401,"Invalid login details.");
  req.session.regenerate(err=>{if(err)return fail(res,500,"Could not start session.");req.session.user={id:u.id,username:u.username,email:u.email,role:u.role};req.session.csrf=require("crypto").randomBytes(24).toString("hex");res.json({ok:true,user:req.session.user,csrf:req.session.csrf});});
});
app.post("/api/logout",requireAuth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/campaigns",(req,res)=>{
  const rows=db.prepare("SELECT id,title,category,description,requirements FROM campaigns WHERE active=1 ORDER BY id DESC").all();
  res.json({campaigns:rows});
});
app.post("/api/claims",requireAuth,(req,res)=>{
  const campaignId=Number(req.body.campaignId),uid=clean(req.body.playerUid,32),details=clean(req.body.details,1000);
  if(!Number.isInteger(campaignId)||campaignId<1||!uid||!details) return fail(res,400,"Complete all claim fields.");
  if(!/^[a-zA-Z0-9_-]{3,32}$/.test(uid)) return fail(res,400,"Check the Player UID format.");
  const campaign=db.prepare("SELECT id FROM campaigns WHERE id=? AND active=1").get(campaignId);
  if(!campaign)return fail(res,404,"Campaign not found or closed.");
  const existing=db.prepare("SELECT id FROM claims WHERE user_id=? AND campaign_id=? AND status='pending'").get(req.session.user.id,campaignId);
  if(existing)return fail(res,409,"You already have a pending claim for this campaign.");
  db.prepare("INSERT INTO claims(user_id,campaign_id,player_uid,details) VALUES(?,?,?,?)").run(req.session.user.id,campaignId,uid,details);
  res.json({ok:true,message:"Claim submitted for administrator review."});
});
app.get("/api/my-claims",requireAuth,(req,res)=>{
  const claims=db.prepare(`SELECT cl.id,cl.player_uid,cl.details,cl.status,cl.admin_note,cl.created_at,c.title
    FROM claims cl JOIN campaigns c ON c.id=cl.campaign_id WHERE cl.user_id=? ORDER BY cl.id DESC`).all(req.session.user.id);
  res.json({claims});
});

app.get("/api/admin/summary",requireAdmin,(req,res)=>{
  res.json({
    users:db.prepare("SELECT COUNT(*) n FROM users WHERE role='user'").get().n,
    pending:db.prepare("SELECT COUNT(*) n FROM claims WHERE status='pending'").get().n,
    approved:db.prepare("SELECT COUNT(*) n FROM claims WHERE status='approved'").get().n,
    campaigns:db.prepare("SELECT COUNT(*) n FROM campaigns").get().n
  });
});
app.get("/api/admin/claims",requireAdmin,(req,res)=>{
  const rows=db.prepare(`SELECT cl.id,cl.player_uid,cl.details,cl.status,cl.admin_note,cl.created_at,
    u.username,u.email,c.title campaign_title FROM claims cl JOIN users u ON u.id=cl.user_id
    JOIN campaigns c ON c.id=cl.campaign_id ORDER BY CASE cl.status WHEN 'pending' THEN 0 ELSE 1 END,cl.id DESC`).all();
  res.json({claims:rows});
});
app.post("/api/admin/claims/:id/review",requireAdmin,(req,res)=>{
  const id=Number(req.params.id),status=clean(req.body.status,16),note=clean(req.body.note,500);
  if(!Number.isInteger(id)||!["approved","rejected"].includes(status))return fail(res,400,"Invalid review action.");
  const info=db.prepare("UPDATE claims SET status=?,admin_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").run(status,note,id);
  if(!info.changes)return fail(res,404,"Pending claim not found.");
  res.json({ok:true,message:`Claim ${status}. This is an administrative review only, not proof of CP delivery.`});
});
app.get("/api/admin/users",requireAdmin,(req,res)=>{
  res.json({users:db.prepare("SELECT id,username,email,role,disabled,created_at FROM users ORDER BY id DESC LIMIT 500").all()});
});
app.post("/api/admin/users/:id/disable",requireAdmin,(req,res)=>{
  const id=Number(req.params.id),disabled=Boolean(req.body.disabled);
  if(!Number.isInteger(id)||id===req.session.user.id)return fail(res,400,"Invalid account.");
  const info=db.prepare("UPDATE users SET disabled=? WHERE id=? AND role='user'").run(disabled?1:0,id);
  if(!info.changes)return fail(res,404,"User not found.");
  res.json({ok:true});
});
app.post("/api/admin/campaigns",requireAdmin,(req,res)=>{
  const title=clean(req.body.title,100),category=clean(req.body.category,40),description=clean(req.body.description,700),requirements=clean(req.body.requirements,700);
  if(!title||!category||!description||!requirements)return fail(res,400,"Complete every campaign field.");
  const info=db.prepare("INSERT INTO campaigns(title,category,description,requirements) VALUES(?,?,?,?)").run(title,category,description,requirements);
  res.json({ok:true,id:Number(info.lastInsertRowid)});
});
app.post("/api/admin/campaigns/:id/toggle",requireAdmin,(req,res)=>{
  const id=Number(req.params.id),active=Boolean(req.body.active);
  const info=db.prepare("UPDATE campaigns SET active=? WHERE id=?").run(active?1:0,id);
  if(!info.changes)return fail(res,404,"Campaign not found.");
  res.json({ok:true});
});
app.get("/api/admin/campaigns",requireAdmin,(req,res)=>{
  res.json({campaigns:db.prepare("SELECT * FROM campaigns ORDER BY id DESC").all()});
});

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"Unexpected server error."});});
app.listen(PORT,()=>console.log(`RUDY CP REWARDS V2 running on http://localhost:${PORT}`));
