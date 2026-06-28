import bcrypt from 'bcryptjs'
import dotenv from 'dotenv'
import { query, pool } from '../db.js'

dotenv.config()

const username = String(process.argv[2] || '').trim()
const password = String(process.argv[3] || '')

if (!username || !password) {
  console.error('Usage: npm run seed:admin -- <username> <password>')
  process.exit(1)
}

try {
  const passwordHash = await bcrypt.hash(password, 10)

  const result = await query(
    `
      INSERT INTO users (username, password_hash, role)
      VALUES ($1, $2, 'admin')
      ON CONFLICT (username)
      DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
      RETURNING id, username, role
    `,
    [username, passwordHash],
  )

  console.log('Admin user ready:', result.rows[0])
} catch (error) {
  console.error('Failed to seed admin user:', error)
  process.exitCode = 1
} finally {
  await pool.end()
}
