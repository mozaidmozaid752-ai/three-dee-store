'use strict';
require('dotenv').config();
const express=require('express');
const helmet=require('helmet');
const session=require('express-session');
const SQLiteStore=require('connect-sqlite3')(session);
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');
const rateLimit=require('express-rate-limit');
const path=require('path');
const required=['ADMIN_PASSWORDS_JSON','SESSION_SECRET'];
for(const key of required) if(!process.env[key]) throw new Error('Missing required environment variable: '+key);
if(process.env.SESSION_SECRET.length<32) throw new Error('SESSION_SECRET must be at least 32 characters.');
let passwords;
try{passwords=JSON.parse(process.env.ADMIN_PASSWORDS_JSON)}catch{throw new Error('ADMIN_PASSWORDS_JSON must be a JSON array.')}
if(!Array.isArray(passwords)||passwords.length!==2||passwords.some(p=>typeof p!=='string'||p.length<14)||new Set(passwords).size!==2) throw new Error('Configure exactly two different admin passwords of at least 14 characters.');
const app=express();
const db=new Database(process.env.DB_PATH||path.join(__dirname,'store.sqlite'));
db.pragma('journal_mode=WAL');
db.exec('CREATE TABLE IF NOT EXISTS admin_passwords(id INTEGER PRIMARY KEY,password_hash TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
if(db.prepare('SELECT COUNT(*) n FROM admin_passwords').get().n===0){const insert=db.prepare('INSERT INTO admin_passwords(password_hash) VALUES(?)');db.transaction(()=>passwords.forEach(p=>insert.run(bcrypt.hashSync(p,12))))();}
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'10kb'}));
app.use(session({name:'three_dee_admin_sid',secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,rolling:true,store:new SQLiteStore({db:'sessions.sqlite',dir:__dirname}),cookie:{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',maxAge:28800000}}));
const limiter=rateLimit({windowMs:900000,limit:8,standardHeaders:'draft-7',legacyHeaders:false,message:{error:'Invalid Password'}});
function requireAdmin(req,res,next){if(!req.session.adminId)return res.status(401).json({error:'Admin authentication required.'});next();}
app.post('/api/admin/login',limiter,async(req,res)=>{const pass=typeof req.body.password==='string'?req.body.password:'';const rows=db.prepare('SELECT id,password_hash FROM admin_passwords ORDER BY id').all();let matched=null;for(const row of rows){if(await bcrypt.compare(pass,row.password_hash).catch(()=>false))matched=row;}if(!matched)return res.status(401).json({error:'Invalid Password'});req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not start secure session.'});req.session.adminId=matched.id;req.session.save(e=>e?res.status(500).json({error:'Could not save secure session.'}):res.json({ok:true}));});});
app.get('/api/admin/me',requireAdmin,(req,res)=>res.json({authenticated:true}));
app.post('/api/admin/logout',(req,res)=>req.session.destroy(err=>{if(err)return res.status(500).json({error:'Logout failed.'});res.clearCookie('three_dee_admin_sid',{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production'});res.json({ok:true});}));
app.get('/api/admin/dashboard',requireAdmin,(req,res)=>res.json({ok:true}));
app.use(express.static(path.join(__dirname,'public'),{index:'index.html'}));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(Number(process.env.PORT||3000),()=>console.log('THREE.DEE server listening'));
