const express = require('express');
const { MongoClient } = require('mongodb');
const { v4: uuid } = require('uuid');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path'); // Only used for express.static path joining, but we don't serve static files here.

const app = express();
app.use(express.json());

// --- Dependencies Logic Consolidated ---

// mongo.js content
const MONGO_URI = process.env.MONGO_URI;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

let db = null;
let initPromise = null;

async function connectToMongo(uri) {
  const client = new MongoClient(uri);
  await client.connect();
  const dbInstance = client.db('lua_protector');
  // TTL index for token cleanup
  await dbInstance.collection('secure_lua_runs_v5').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return dbInstance;
}

async function initDb() {
  if (db) return db;
  if (!initPromise) {
    initPromise = (async () => {
      console.log("Initializing database connection...");
      db = await connectToMongo(MONGO_URI);
      console.log("Database connected successfully.");

      const admins = db.collection('secure_lua_admins_v5');
      const admin = await admins.findOne({ username: ADMIN_USERNAME });
      if (!admin) {
        console.log("Creating default admin user.");
        const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
        await admins.insertOne({ username: ADMIN_USERNAME, passwordHash: hash, sessionToken: null });
      }
      return db;
    })().catch(err => {
      console.error("CRITICAL DB INIT ERROR:", err.message);
      // Re-throw to propagate the crash error
      throw new Error("Failed to initialize database connection. Check MONGO_URI and IP whitelist."); 
    });
  }
  return initPromise;
}

// encryption.js content
function base64Encode(str) {
  return Buffer.from(str).toString('base64');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

// utils.js content
/**
 * CHECK IF THE USER-AGENT IS FROM AN ALLOWED EXECUTOR ENVIRONMENT.
 * This function uses the strict browser-blocking logic you requested,
 * updated with the comprehensive list of executor identifiers.
 */
function isAllowedUA(userAgent) {
  if (!userAgent) {
    return false;
  }
  
  const ua = userAgent.toLowerCase();
  
  // List of common browser identifiers to block
  const browserPatterns = [
    'mozilla',
    'chrome',
    'safari',
    'firefox',
    'edge',
    'opera',
    'brave'
  ];

  // Expanded list of allowed executor/client identifiers
  const executorPatterns = [
    'synapse',
    'krnl',
    'fluxus',
    'script-ware',
    'scriptware',
    'sentinel',
    'electron',
    'executor',
    'roblox', // Roblox itself
    'exploit',
    // New additions based on your request:
    'delta',
    'sirhurt',
    'xeno',
    'solara', 
    'potassium',
    'bunni',
    'lx63',
    'cryptic',
    'volcano',
    'wave',
    'zenith'
  ];

  // 1. Check if it looks like a browser
  const isBrowser = browserPatterns.some(pattern => ua.includes(pattern));

  // 2. If it is a browser, but also contains a strong executor identifier, allow it.
  //    Otherwise, block the browser.
  const isExplicitExecutor = executorPatterns.some(pattern => ua.includes(pattern));

  if (isBrowser && !isExplicitExecutor) {
    // If it looks like a browser AND does NOT contain any executor name, BLOCK it.
    return false;
  }
  
  // 3. If it is an explicit executor (isExplicitExecutor == true), OR it is not
  //    a browser at all (isBrowser == false), allow it.
  //    This logic ensures that if the client is not a known browser, or if it
  //    explicitly names an executor, it is allowed to proceed.
  return isExplicitExecutor || !isBrowser;
}

// --- Express Middleware & Routes ---

app.use(async (req, res, next) => {
  try { 
    await initDb(); 
    next(); 
  } 
  catch(err){ 
    // This is the functional error handler that returns JSON
    console.error("Request failed during DB init:", err);
    res.status(500).json({ error: 'Failed to initialize database connection. Check MONGO_URI and IP whitelist.' }); 
  }
});

// Admin login route (POST /admin/login)
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

// Create script route (POST /admin/create)
app.post('/admin/create', async (req,res)=>{
  const { payload } = req.body;
  const sessionToken = req.headers['x-session-token'];
  const admins = db.collection('secure_lua_admins_v5');
  const admin = await admins.findOne({ sessionToken });
  if(!admin) return res.status(403).json({ error:'Unauthorized' });
  
  const scripts = db.collection('secure_lua_scripts_v5');
  const id = uuid();
  await scripts.insertOne({ id,payload });
  
  // Note: Vercel routes handle the host part correctly
  const rawUrl = `https://${req.headers.host}/raw/${id}`; 
  res.json({ rawUrl });
});

// Generate loader (GET /raw/:id)
app.get('/raw/:id', async (req,res)=>{
  const { id } = req.params;
  const ua = req.headers['user-agent'];
  if(!isAllowedUA(ua)) return res.status(403).send('Forbidden');

  const scripts = db.collection('secure_lua_scripts_v5');
  const script = await scripts.findOne({ id });
  if(!script) return res.status(404).send('Not found');

  const token = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now()+30000); // 30 seconds

  const runs = db.collection('secure_lua_runs_v5');
  await runs.insertOne({ token,nonce,scriptId:id,expiresAt,used:false });

  // Lua HMAC-SHA256 Implementation 
  const loaderPayload = `
-- Pure Lua HMAC-SHA256 (Simplified and robust, assuming bitwise functions are available)
local function sha256_hex(s)
  local hash = require("sha2") -- Executor must provide this global module
  if not hash then error("Missing 'sha2' module for HMAC") end
  return hash.sha256(s)
end

local function hmac_sha256(key,msg)
  local blocksize = 64
  local key_bytes = key
  
  if #key_bytes > blocksize then 
    key_bytes = sha256_hex(key_bytes)
  end
  
  local key_padded = key_bytes .. string.rep("\\0", blocksize - #key_bytes)
  
  local opad, ipad = "", ""
  for i = 1, blocksize do
    local c = string.byte(key_padded, i) or 0
    opad = opad .. string.char(bit.bxor(c, 0x5c))
    ipad = ipad .. string.char(bit.bxor(c, 0x36))
  end
  
  return sha256_hex(opad .. sha256_hex(ipad .. msg))
end

local HttpService = game:GetService("HttpService")
local playerId = game.Players.LocalPlayer.UserId
local ts = os.time()

-- Data string must match server calculation: token + nonce + playerId + ts
local data = "${token}".."${nonce}"..tostring(playerId)..tostring(ts) 
local proof = hmac_sha256("${token}", data)

local blobUrl = "https://${req.headers.host}/blob/${id}"

local ok,res = pcall(function()
  return HttpService:RequestAsync({
    Url=blobUrl,
    Method="GET",
    Headers={
      ["x-run-token"]="${token}",
      ["x-run-proof"]=proof,
      ["x-ts"]=tostring(ts),
      ["x-player-id"]=tostring(playerId)
    },
    Timeout=10
  })
end)
if ok and res and res.StatusCode==200 then
  loadstring(res.Body)()
end
`;

  const loader = base64Encode(loaderPayload);
  res.setHeader('Content-Type','text/plain');
  res.send(loader);
});

// Serve script and verify security (GET /blob/:id)
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
  if(!run.value) return res.status(403).send('Invalid token (single-use or expired)');

  // SERVER-SIDE HMAC VERIFICATION: Key is token, data is token+nonce+playerId+tsStr
  const data = token + run.value.nonce + playerId + tsStr;
  const expectedProof = hmacSha256(token,data);
  
  if(proof!==expectedProof) {
    // If proof fails, mark it as unused again (optional, for debugging)
    await runs.updateOne({ _id: run.value._id }, { $set: { used: false, usedAt: null, usedBy: null } });
    return res.status(403).send('Invalid proof (HMAC check failed)');
  }

  const scripts = db.collection('secure_lua_scripts_v5');
  const script = await scripts.findOne({id});
  if(!script) return res.status(404).send('Not found');

  res.setHeader('Content-Type','text/plain');
  res.send(script.payload);
});

module.exports = app;

