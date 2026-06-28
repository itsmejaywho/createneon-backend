import dotenv from 'dotenv'
import pg from 'pg'

dotenv.config()

const { Pool } = pg

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not set. Add it to createneon-backend/.env')
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
})

export async function query(text, params = []) {
  return pool.query(text, params)
}
