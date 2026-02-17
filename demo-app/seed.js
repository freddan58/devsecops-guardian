// ============================================================
// Database Seeder - Creates tables and sample data
// Run: node seed.js
// ============================================================

const { getDatabase, closeDatabase } = require('./config/database');
const { hashPassword } = require('./utils/auth');

async function seed() {
  const db = getDatabase();

  console.log('Creating tables...');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'customer',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      account_number TEXT UNIQUE NOT NULL,
      owner_name TEXT NOT NULL,
      account_type TEXT DEFAULT 'checking',
      balance REAL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS transfers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_account_id INTEGER NOT NULL,
      to_account_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      description TEXT,
      user_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (from_account_id) REFERENCES accounts(id),
      FOREIGN KEY (to_account_id) REFERENCES accounts(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  console.log('Seeding users...');

  const password1 = await hashPassword('password123');
  const password2 = await hashPassword('admin456');
  const password3 = await hashPassword('customer789');

  const insertUser = db.prepare(
    'INSERT OR IGNORE INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)'
  );

  insertUser.run('jdoe', 'john.doe@example.com', password1, 'customer');
  insertUser.run('admin', 'admin@bankapp.com', password2, 'admin');
  insertUser.run('msmith', 'maria.smith@example.com', password3, 'customer');

  console.log('Seeding accounts...');

  const insertAccount = db.prepare(
    'INSERT OR IGNORE INTO accounts (user_id, account_number, owner_name, account_type, balance) VALUES (?, ?, ?, ?, ?)'
  );

  insertAccount.run(1, 'ACC-001-2024-CHK', 'John Doe', 'checking', 5250.75);
  insertAccount.run(1, 'ACC-001-2024-SAV', 'John Doe', 'savings', 12500.00);
  insertAccount.run(2, 'ACC-002-2024-CHK', 'Admin User', 'checking', 1000000.00);
  insertAccount.run(3, 'ACC-003-2024-CHK', 'Maria Smith', 'checking', 8750.50);
  insertAccount.run(3, 'ACC-003-2024-SAV', 'Maria Smith', 'savings', 45000.00);

  console.log('Seeding transfers...');

  const insertTransfer = db.prepare(
    'INSERT OR IGNORE INTO transfers (from_account_id, to_account_id, amount, description, user_id) VALUES (?, ?, ?, ?, ?)'
  );

  insertTransfer.run(1, 4, 500.00, 'Monthly rent payment', 1);
  insertTransfer.run(4, 1, 100.00, 'Refund for overpayment', 3);
  insertTransfer.run(1, 2, 1000.00, 'Transfer to savings', 1);

  console.log('Database seeded successfully!');
  closeDatabase();
}

seed().catch(err => {
  console.error('Seed error:', err);
  closeDatabase();
  process.exit(1);
});
