const express = require('express');
const { v4: uuid } = require('uuid');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
// FIX: Changed relative path from '..' to '.' since files are now in the same directory
const connectToMongo = require('./mongo.js'); 
const { base64Encode, hmacSha256 } = require('./encryption.js');
const { isAllowedUA } = require('./utils.js');

const app = express();
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

let db = null;
let initPromise = null;

async function initDb() {
  if (db) return db;
  if (!initPromise) {
    initPromise = (async () => {
      try { // Added try/catch around connection for better error feedback
        db = await connectToMongo(MONGO_URI);
        const admins = db.collection('secure_lua_admins_v5');
        const admin = await admins.findOne({ username: ADMIN_USERNAME });
        if (!admin) {
          const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
          await admins.insertOne({ username: ADMIN_USERNAME, passwordHash: hash, sessionToken: null });
        }
        return db;
      } catch (err) {
        console.error("MongoDB Initialization Error:", err);
        // Re-throw the error to ensure the calling function catches it
        throw new Error("Failed to initialize database connection."); 
      }
    })();
  }
  return initPromise;
}

app.use(async (req, res, next) => {
  try { await initDb(); next(); }
  // This catch block is now more likely to run if the DB fails AFTER startup
  catch(err){ res.status(500).json({error:'Database connection failed'}); }
});

// admin login
app.post('/admin/login', async (req,res)=>{
  const { username,password } = req.body;
  const admins = db.collection('secure_lua_admins_v5');
  const admin = await admins.findOne({ username });
  if(!admin || !await bcrypt.compare(password, admin.passwordHash))
    return res.json({ error: 'Invalid credentials' });
  const sessionToken = uuid();
  await admins.updateOne({ username }, { $set:{ sessionToken }});
  res.json({ sessionToken });
});

// create script
app.post('/admin/create', async (req,res)=>{
  const { payload } = req.body;
  const sessionToken = req.headers['x-session-token'];
  const admins = db.collection('secure_lua_admins_v5');
  const admin = await admins.findOne({ sessionToken });
  if(!admin) return res.status(403).json({ error:'Unauthorized' });
  const scripts = db.collection('secure_lua_scripts_v5');
  const id = uuid();
  await scripts.insertOne({ id,payload });
  const rawUrl = `https://${req.headers.host}/api/raw/${id}`;
  res.json({ rawUrl });
});

// generate loader
app.get('/raw/:id', async (req,res)=>{
  const { id } = req.params;
  const ua = req.headers['user-agent'];
  if(!isAllowedUA(ua)) return res.status(403).send('Forbidden');

  const scripts = db.collection('secure_lua_scripts_v5');
  const script = await scripts.findOne({ id });
  if(!script) return res.status(404).send('Not found');

  const token = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now()+30000);

  const runs = db.collection('secure_lua_runs_v5');
  await runs.insertOne({ token,nonce,scriptId:id,expiresAt,used:false });

  const loaderPayload = `
-- Pure Lua HMAC-SHA256 (Executor must provide a 'hash.sha256' function)
local HttpService = game:GetService("HttpService")
local playerId = game.Players.LocalPlayer.UserId
local token = "${token}"
local nonce = "${nonce}"
local ts = os.time()
local blobUrl = "https://${req.headers.host}/api/blob/${id}"

-- Key: token. Data: token + nonce + playerId + ts
local data = token..nonce..tostring(playerId)..tostring(ts) 
local proof = hash.sha256(token, data)

local ok,res = pcall(function()
  return HttpService:RequestAsync({
    Url=blobUrl,
    Method="GET",
    Headers={
      ["x-run-token"]=token,
      ["x-run-proof"]=proof,
      ["x-ts"]=tostring(ts),
      ["x-player-id"]=tostring(playerId)
    },
    Timeout=10
  })
end)
if ok and res and res.StatusCode==200 then
  -- Suppress output before loading the script
  local oldPrint, oldWarn = print, warn
  print = function() end
  warn = function() end
  
  local success, err = pcall(function()
      loadstring(res.Body)()
  end)

  -- Restore output
  print, warn = oldPrint, oldWarn
  
  if not success then error("tamper/fetch fail: "..tostring(err), 2) end
end
`;

  const loader = base64Encode(loaderPayload);
  res.setHeader('Content-Type','text/plain');
  res.send(loader);
});

// serve script
app.get('/blob/:id', async (req,res)=>{
  const { id } = req.params;
  const ua = req.headers['user-agent'];
  if(!isAllowedUA(ua)) return res.status(403).send('Forbidden');

  const token = req.headers['x-run-token'];
  const playerId = req.headers['x-player-id'];
  const proof = req.headers['x-run-proof'];
  const tsStr = req.headers['x-ts'];
  if(!token||!playerId||!proof||!tsStr) return res.status(403).send('Missing headers');

  const ts = parseInt(tsStr);
  const now = Math.floor(Date.now()/1000);
  if(Math.abs(now-ts)>10) return res.status(403).send('Invalid timestamp');

  const runs = db.collection('secure_lua_runs_v5');
  const run = await runs.findOneAndUpdate(
    { token,scriptId:id,used:false,expiresAt:{$gt:new Date()} },
    { $set:{used:true,usedAt:new Date(),usedBy:playerId} },
    { returnDocument:'before' }
  );
  if(!run.value) return res.status(403).send('Invalid token or token already used');

  const data = token + run.value.nonce + playerId + tsStr;
  const expectedProof = hmacSha256(token,data);
  if(proof!==expectedProof) return res.status(403).send('Invalid proof');

  const scripts = db.collection('secure_lua_scripts_v5');
  const script = await scripts.findOne({id});
  if(!script) return res.status(404).send('Not found');

  res.setHeader('Content-Type','text/plain');
  res.send(script.payload);
});

module.exports = app;

