const { MongoClient } = require('mongodb');

async function connectToMongo(uri) {
  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db('lua_protector');
  await db.collection('secure_lua_runs_v5').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  return db;
}

module.exports = connectToMongo;
