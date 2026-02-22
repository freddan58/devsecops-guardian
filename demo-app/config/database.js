// ============================================================
// Database configuration
// ============================================================

const Database = require('better-sqlite3');
const path = require('path');

// FIXED: Fail fast if required secrets are missing instead of defaulting to empty strings
const API_KEY = process.env.API_KEY;
const DB_SECRET = process.env.DB_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!API_KEY || !DB_SECRET || !ENCRYPTION_KEY) {
  throw new Error('Missing required environment variables: API_KEY, DB_SECRET, and ENCRYPTION_KEY must be set');
}

const DB_CONFIG = {
  API_KEY,
  DB_SECRET,
  ENCRYPTION_KEY
};

const DB_PATH = path.join(__dirname, '..', 'banking.db');

let db;

function getDatabase() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
  }
  return db;
}

function closeDatabase() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDatabase, closeDatabase, DB_CONFIG };