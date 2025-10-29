const express = require('express');
const { MongoClient } = require('mongodb');
const { v4: uuid } = require('uuid');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// --- Database Connection and Initialization ---

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
      throw new Error("Failed to initialize database connection. Check MONGO_URI and IP whitelist."); 
    });
  }
  return initPromise;
}

// --- Utility Functions (Encryption & User-Agent) ---

function base64Encode(str) {
  return Buffer.from(str).toString('base64');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

/**
 * Generates random, ugly variable names.
 */
function generateRandomVarName() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let name = '';
  const length = Math.floor(Math.random() * 5) + 6; // 6-10 chars
  for (let j = 0; j < length; j++) {
    name += chars[Math.floor(Math.random() * chars.length)];
  }
  return name;
}

/**
 * Wraps the raw Lua code in an extremely compressed and ugly Base64 decoder wrapper.
 */
function encryptLuaScript(code) {
  const base64Code = Buffer.from(code).toString('base64');
  
  // Generating extremely compressed and random variable names
  const V1 = generateRandomVarName(); // payload
  const V2 = generateRandomVarName(); // decoder func
  const V3 = generateRandomVarName(); // map
  const V4 = generateRandomVarName(); // lookup
  const V5 = generateRandomVarName(); // result string
  
  // This is the highly compressed, ugly, and reliable pure Lua Base64 Decoder (Loop-based arithmetic)
  const decoderLua = `
local ${V1}="${base64Code}"
local ${V3}="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local ${V4}={}
for I=1,#${V3} do ${V4}[${V3}:sub(I,I)]=I-1 end
local ${V2}=function(S)
  local ${V5}=""
  for I=1,#S,4 do
    local I1,I2,I3,I4=${V4}[S:sub(I,I)],${V4}[S:sub(I+1,I+1)],${V4}[S:sub(I+2,I+2)],${V4}[S:sub(I+3,I+3)]
    ${V5}=${V5}..string.char(I1*4+math.floor(I2/16))
    if I3 and S:sub(I+2,I+2)~="=" then
      ${V5}=${V5}..string.char((I2%16)*16+math.floor(I3/4))
    end
    if I4 and S:sub(I+3,I+3)~="=" then
      ${V5}=${V5}..string.char((I3%4)*64+I4)
    end
  end
  return ${V5}
end
loadstring(${V2}(${V1}))()
`.trim().replace(/\n/g, '').replace(/;;/g, ';'); // Final cleanup for maximum compression

  return decoderLua;
}

/**
 * CHECK IF THE USER-AGENT IS FROM AN ALLOWED EXECUTOR ENVIRONMENT.
 */
function isAllowedUA(userAgent) {
  if (!userAgent) {
    return false;
  }
  
  const ua = userAgent.toLowerCase();
  
  const browserPatterns = [
    'mozilla', 'chrome', 'safari', 'firefox',
    'edge', 'opera', 'brave'
  ];

  const executorPatterns = [
    'synapse', 'krnl', 'fluxus', 'script-ware', 'scriptware', 'sentinel',
    'electron', 'executor', 'roblox', 'exploit', 'delta', 'sirhurt',
    'xeno', 'solara', 'potassium', 'bunni', 'lx63', 'cryptic',
    'volcano', 'wave', 'zenith'
  ];

  const isBrowser = browserPatterns.some(pattern => ua.includes(pattern));
  const isExplicitExecutor = executorPatterns.some(pattern => ua.includes(pattern));

  if (isBrowser && !isExplicitExecutor) {
    return false;
  }
  
  return isExplicitExecutor || !isBrowser;
}

// --- Express Middleware & Routes ---

app.use(async (req, res, next) => {
  try { 
    await initDb(); 
    next(); 
  } 
  catch(err){ 
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

// Create script route (POST /admin/create) - UPDATED TO OBFUSCATE
app.post('/admin/create', async (req,res)=>{
  const { payload } = req.body; 
  const sessionToken = req.headers['x-session-token'];
  const admins = db.collection('secure_lua_admins_v5');
  const admin = await admins.findOne({ sessionToken });
  if(!admin) return res.status(403).json({ error:'Unauthorized' });
  
  const obfuscatedPayload = encryptLuaScript(payload);

  const scripts = db.collection('secure_lua_scripts_v5');
  const id = uuid();
  
  await scripts.insertOne({ id, payload: obfuscatedPayload }); 
  
  const rawUrl = `https://${req.headers.host}/raw/${id}`; 
  res.json({ rawUrl });
});

// Generate loader (GET /raw/:id) - LOADER IS BASE64 ENCODED
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

  const loaderPayload = `
-- Pure Lua HMAC-SHA256 (Assuming 'sha2' and 'bit' modules are available)
local function sha256_hex(s)
  local hash = require("sha2") 
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

// Serve script and verify security (GET /blob/:id) - RETURNS OBFUSCATED LUA
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

