import bcrypt from 'bcryptjs'
import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import jwt from 'jsonwebtoken'
import { pool, query } from './db.js'
import { registerSwagger } from './swagger.js'

dotenv.config()

const app = express()
const port = Number(process.env.PORT) || 4000
const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173'
const loginAttemptWindowMs = 15 * 60 * 1000
const maxLoginAttempts = 5
const loginAttempts = new Map()
const jwtSecret = process.env.JWT_SECRET
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '8h'

if (!jwtSecret) {
  throw new Error('JWT_SECRET is not set. Add it to createneon-backend/.env')
}

app.disable('x-powered-by')
app.use(cors({ origin: corsOrigin }))
app.use(express.json({ limit: '100kb' }))

const createOrdersTableSql = `
  CREATE TABLE IF NOT EXISTS neon_design_orders (
    id SERIAL PRIMARY KEY,
    step_1_text TEXT NOT NULL,
    step_1_alignment VARCHAR(20) NOT NULL,
    step_1_font_id VARCHAR(100) NOT NULL,
    step_1_font_name VARCHAR(100) NOT NULL,
    step_2_color_id VARCHAR(100) NOT NULL,
    step_2_color_name VARCHAR(100) NOT NULL,
    step_3_width_cm INTEGER NOT NULL,
    step_3_height_cm INTEGER NOT NULL,
    step_4_location_id VARCHAR(50) NOT NULL,
    step_4_location_label VARCHAR(100) NOT NULL,
    quoted_price INTEGER NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`

async function ensureOrdersTable() {
  await query(createOrdersTableSql)
  await query(`
    ALTER TABLE neon_design_orders
    ADD COLUMN IF NOT EXISTS step_1_font_name VARCHAR(100)
  `)
}

function getClientKey(request, username = '') {
  const forwardedFor = request.headers['x-forwarded-for']
  const ip = Array.isArray(forwardedFor)
    ? forwardedFor[0]
    : String(forwardedFor || request.ip || request.socket?.remoteAddress || 'unknown')
        .split(',')[0]
        .trim()

  return `${ip}:${username.toLowerCase()}`
}

function readLoginAttemptState(key) {
  const now = Date.now()
  const existing = loginAttempts.get(key)

  if (!existing || existing.expiresAt <= now) {
    loginAttempts.delete(key)
    return { count: 0, expiresAt: now + loginAttemptWindowMs }
  }

  return existing
}

function registerFailedLogin(key) {
  const current = readLoginAttemptState(key)
  loginAttempts.set(key, {
    count: current.count + 1,
    expiresAt: current.expiresAt,
  })
}

function clearFailedLogins(key) {
  loginAttempts.delete(key)
}

function createAccessToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      username: user.username,
      role: user.role,
    },
    jwtSecret,
    { expiresIn: jwtExpiresIn },
  )
}

function authenticateToken(request, response, next) {
  const authorization = request.headers.authorization || ''

  if (!authorization.startsWith('Bearer ')) {
    response.status(401).json({ error: 'Authorization token is required.' })
    return
  }

  const token = authorization.slice('Bearer '.length).trim()

  try {
    request.user = jwt.verify(token, jwtSecret)
    next()
  } catch {
    response.status(401).json({ error: 'Invalid or expired token.' })
  }
}

registerSwagger(app, port)

app.get('/health', async (_request, response) => {
  try {
    await query('SELECT 1')
    response.json({ ok: true })
  } catch (error) {
    console.error('Health check failed:', error)
    response.status(500).json({ ok: false, error: 'Service unavailable.' })
  }
})

app.post('/api/auth/login', async (request, response) => {
  const username = String(request.body?.username || '').trim()
  const password = String(request.body?.password || '')
  const loginAttemptKey = getClientKey(request, username)
  const attemptState = readLoginAttemptState(loginAttemptKey)

  if (!username || !password) {
    response.status(400).json({ error: 'Username and password are required.' })
    return
  }

  if (attemptState.count >= maxLoginAttempts) {
    response.status(429).json({
      error: 'Too many login attempts. Try again in 15 minutes.',
    })
    return
  }

  try {
    const result = await query(
      'SELECT id, username, password_hash, role FROM users WHERE username = $1 LIMIT 1',
      [username],
    )

    const user = result.rows[0]

    if (!user) {
      registerFailedLogin(loginAttemptKey)
      response.status(401).json({ error: 'Invalid username or password.' })
      return
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash)

    if (!passwordMatches) {
      registerFailedLogin(loginAttemptKey)
      response.status(401).json({ error: 'Invalid username or password.' })
      return
    }

    clearFailedLogins(loginAttemptKey)
    const token = createAccessToken(user)

    response.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    })
  } catch (error) {
    console.error('Login failed:', error)
    response.status(500).json({ error: 'Unable to verify login.' })
  }
})

app.get('/api/auth/me', authenticateToken, (request, response) => {
  response.json({
    user: {
      id: Number(request.user.sub),
      username: request.user.username,
      role: request.user.role,
    },
  })
})

app.post('/api/design-orders', async (request, response) => {
  const {
    text,
    alignment,
    fontId,
    fontName,
    colorId,
    colorName,
    widthCm,
    heightCm,
    locationId,
    locationLabel,
    quotedPrice,
  } = request.body ?? {}

  const normalizedText = String(text || '').trim()
  const normalizedAlignment = String(alignment || '').trim()
  const normalizedFontId = String(fontId || '').trim()
  const normalizedFontName = String(fontName || normalizedFontId).trim()
  const normalizedColorId = String(colorId || '').trim()
  const normalizedColorName = String(colorName || '').trim()
  const normalizedLocationId = String(locationId || '').trim()
  const normalizedLocationLabel = String(locationLabel || '').trim()
  const normalizedWidth = Number(widthCm)
  const normalizedHeight = Number(heightCm)
  const normalizedQuotedPrice = Number(quotedPrice)

  if (
    !normalizedText ||
    !normalizedAlignment ||
    !normalizedFontId ||
    !normalizedFontName ||
    !normalizedColorId ||
    !normalizedColorName ||
    !normalizedLocationId ||
    !normalizedLocationLabel ||
    !Number.isFinite(normalizedWidth) ||
    !Number.isFinite(normalizedHeight) ||
    !Number.isFinite(normalizedQuotedPrice)
  ) {
    response
      .status(400)
      .json({ error: 'Complete all four design steps before saving.' })
    return
  }

  try {
    await ensureOrdersTable()

    const result = await query(
      `
        INSERT INTO neon_design_orders (
          step_1_text,
          step_1_alignment,
          step_1_font_id,
          step_1_font_name,
          step_2_color_id,
          step_2_color_name,
          step_3_width_cm,
          step_3_height_cm,
          step_4_location_id,
          step_4_location_label,
          quoted_price
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id, submitted_at
      `,
      [
        normalizedText,
        normalizedAlignment,
        normalizedFontId,
        normalizedFontName,
        normalizedColorId,
        normalizedColorName,
        normalizedWidth,
        normalizedHeight,
        normalizedLocationId,
        normalizedLocationLabel,
        normalizedQuotedPrice,
      ],
    )

    response.status(201).json({
      id: result.rows[0].id,
      submittedAt: result.rows[0].submitted_at,
    })
  } catch (error) {
    console.error('Saving design order failed:', error)
    response.status(500).json({ error: 'Unable to save your design right now.' })
  }
})

ensureOrdersTable()
  .then(() => {
    app.listen(port, () => {
      console.log(`Backend listening on http://localhost:${port}`)
    })
  })
  .catch((error) => {
    console.error('Failed to prepare database:', error)
    process.exit(1)
  })

process.on('SIGINT', async () => {
  await pool.end()
  process.exit(0)
})
