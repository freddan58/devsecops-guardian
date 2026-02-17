// ============================================================
// FIXED: Removed hardcoded API Key, DB secret, and encryption key
// Secrets are now loaded from environment variables for security
// ============================================================

const Database = require('better-sqlite3');
const path = require('path');

// FIX: Load secrets from environment variables to prevent exposure of hardcoded credentials
const DB_CONFIG = {
  API_KEY: process.env.API_KEY,
  DB_SECRET: process.env.DB_SECRET,
  ENCRYPTION_KEY: process.env.ENCRYPTION_KEY
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