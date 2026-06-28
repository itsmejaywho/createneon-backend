#!/usr/bin/env node
import bcrypt from 'bcryptjs';
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

function buildConnectionStringFromPgEnv() {
  const host = process.env.PGHOST;
  const port = process.env.PGPORT || '5432';
  const database = process.env.PGDATABASE;
  const user = process.env.PGUSER;
  const password = process.env.PGPASSWORD;

  if (!host || !database || !user || !password) {
    return null;
  }

  const connectionUrl = new URL('postgresql://localhost');
  connectionUrl.hostname = host;
  connectionUrl.port = port;
  connectionUrl.pathname = `/${database}`;
  connectionUrl.username = user;
  connectionUrl.password = password;

  return connectionUrl.toString();
}

const connectionString = process.env.DATABASE_URL || buildConnectionStringFromPgEnv();

if (!connectionString) {
  console.error('Database connection is not configured. Set DATABASE_URL or the PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD variables.');
  process.exit(1);
}

const pool = new Pool({ connectionString });

async function addUser() {
  try {
    const username = 'user';
    const password = 'admin';
    const role = 'admin';

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO UPDATE SET password_hash = $2, role = $3 RETURNING id, username, role',
      [username, passwordHash, role]
    );

    console.log('✓ User created/updated:', result.rows[0]);
  } catch (error) {
    console.error('✗ Error:', error.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

addUser();

