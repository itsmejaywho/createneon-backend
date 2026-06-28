import dotenv from 'dotenv'
import pg from 'pg'

dotenv.config()

const { Pool } = pg

function buildConnectionStringFromPgEnv() {
  const host = process.env.PGHOST
  const port = process.env.PGPORT || '5432'
  const database = process.env.PGDATABASE
  const user = process.env.PGUSER
  const password = process.env.PGPASSWORD

  if (!host || !database || !user || !password) {
    return null
  }

  const connectionUrl = new URL('postgresql://localhost')
  connectionUrl.hostname = host
  connectionUrl.port = port
  connectionUrl.pathname = `/${database}`
  connectionUrl.username = user
  connectionUrl.password = password

  return connectionUrl.toString()
}

const connectionString = process.env.DATABASE_URL || buildConnectionStringFromPgEnv()

if (!connectionString) {
  throw new Error(
    'Database connection is not configured. Set DATABASE_URL or the PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD variables.',
  )
}

export const pool = new Pool({
  connectionString,
})

export async function query(text, params = []) {
  return pool.query(text, params)
}
