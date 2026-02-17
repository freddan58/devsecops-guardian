// ============================================================
// VULNERABILITY #3: Hardcoded API Key (CWE-798)
// Secret credentials stored directly in source code
// ============================================================

const Database = require('better-sqlite3');
const path = require('path');

// VULNERABLE: Hardcoded credentials in source code
const DB_CONFIG = {
  API_KEY: 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234',
  DB_SECRET: 'super_secret_database_password_2024',
  ENCRYPTION_KEY: 'aes-256-key-do-not-share-1234567890abcdef'
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
