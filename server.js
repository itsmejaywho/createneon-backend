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
const loginAttemptWindowMs = 15 * 60 * 1000
const maxLoginAttempts = 5
const designOrderWindowMs = 5 * 60 * 60 * 1000
const maxDesignOrdersPerDevice = 3
const ordersCacheTtlMs = 30 * 1000
const streamTokenExpiresIn = '2m'
const loginAttempts = new Map()
const designOrderAttempts = new Map()
const orderStreamClients = new Set()
const ordersCache = {
  expiresAt: 0,
  orders: null,
}
const jwtSecret = process.env.JWT_SECRET
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '8h'
const allowedCorsOrigins = String(
  process.env.CORS_ORIGIN ||
    'http://localhost:5173,http://127.0.0.1:5173,https://aboutneon.vercel.app',
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean)

if (!jwtSecret) {
  throw new Error('JWT_SECRET is not set. Add it to createneon-backend/.env')
}

app.disable('x-powered-by')
app.set('trust proxy', 1)
const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedCorsOrigins.includes(origin)) {
      callback(null, true)
      return
    }

    callback(new Error('Origin is not allowed by CORS.'))
  },
  methods: ['GET', 'HEAD', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Id'],
  optionsSuccessStatus: 204,
}

app.use(cors(corsOptions))
app.options('*', cors(corsOptions))
app.use((_request, response, next) => {
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.setHeader('X-Frame-Options', 'DENY')
  response.setHeader('Referrer-Policy', 'no-referrer')
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  next()
})
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

const insertDesignOrderSql = `
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
`

async function ensureOrdersTable() {
  await query(createOrdersTableSql)
  await query(`
    ALTER TABLE neon_design_orders
    ADD COLUMN IF NOT EXISTS step_1_font_name VARCHAR(100)
  `)
}

function getClientKey(request) {
  const forwardedFor = request.headers['x-forwarded-for']

  return (
    Array.isArray(forwardedFor)
      ? forwardedFor[0]
      : String(forwardedFor || request.ip || request.socket?.remoteAddress || 'unknown')
          .split(',')[0]
          .trim()
  )
}

function getLoginAttemptKey(request, username = '') {
  return `${getClientKey(request)}:${username.toLowerCase()}`
}

function getDesignOrderClientKey(request) {
  const deviceId = String(request.headers['x-device-id'] || '').trim()

  if (!/^[a-zA-Z0-9-]{16,128}$/.test(deviceId)) {
    return null
  }

  return `${getClientKey(request)}:${deviceId}`
}

function readWindowAttemptState(store, key, windowMs) {
  const now = Date.now()
  const existing = store.get(key)

  if (!existing || existing.expiresAt <= now) {
    store.delete(key)
    return { count: 0, expiresAt: now + windowMs }
  }

  return existing
}

function writeWindowAttemptState(store, key, current) {
  store.set(key, {
    count: current.count + 1,
    expiresAt: current.expiresAt,
  })
}

function readLoginAttemptState(key) {
  return readWindowAttemptState(loginAttempts, key, loginAttemptWindowMs)
}

function registerFailedLogin(key) {
  writeWindowAttemptState(loginAttempts, key, readLoginAttemptState(key))
}

function clearFailedLogins(key) {
  loginAttempts.delete(key)
}

function readDesignOrderAttemptState(key) {
  return readWindowAttemptState(designOrderAttempts, key, designOrderWindowMs)
}

function registerDesignOrderAttempt(key) {
  writeWindowAttemptState(
    designOrderAttempts,
    key,
    readDesignOrderAttemptState(key),
  )
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

function createStreamToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      role: user.role,
      type: 'orders-stream',
    },
    jwtSecret,
    { expiresIn: streamTokenExpiresIn },
  )
}

function verifyTokenIntoRequest(token, request, response, next) {
  try {
    request.user = jwt.verify(token, jwtSecret)
    next()
  } catch {
    response.status(401).json({ error: 'Invalid or expired token.' })
  }
}

function authenticateToken(request, response, next) {
  const authorization = request.headers.authorization || ''

  if (!authorization.startsWith('Bearer ')) {
    response.status(401).json({ error: 'Authorization token is required.' })
    return
  }

  verifyTokenIntoRequest(
    authorization.slice('Bearer '.length).trim(),
    request,
    response,
    next,
  )
}

function requireAdmin(request, response, next) {
  if (request.user?.role !== 'admin') {
    response.status(403).json({ error: 'Admin access is required.' })
    return
  }

  next()
}

function serializeOrderRow(row) {
  return {
    id: row.id,
    text: row.step_1_text,
    alignment: row.step_1_alignment,
    fontId: row.step_1_font_id,
    fontName: row.step_1_font_name,
    colorId: row.step_2_color_id,
    colorName: row.step_2_color_name,
    widthCm: row.step_3_width_cm,
    heightCm: row.step_3_height_cm,
    locationId: row.step_4_location_id,
    locationLabel: row.step_4_location_label,
    quotedPrice: row.quoted_price,
    submittedAt: row.submitted_at,
  }
}

function invalidateOrdersCache() {
  ordersCache.orders = null
  ordersCache.expiresAt = 0
}

async function loadOrdersFromDatabase() {
  const result = await query(
    `
      SELECT
        id,
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
        quoted_price,
        submitted_at
      FROM neon_design_orders
      ORDER BY submitted_at ASC, id ASC
    `,
  )

  return result.rows.map(serializeOrderRow)
}

async function getCachedOrders() {
  const now = Date.now()

  if (ordersCache.orders && ordersCache.expiresAt > now) {
    return { hit: true, orders: ordersCache.orders }
  }

  const orders = await loadOrdersFromDatabase()
  ordersCache.orders = orders
  ordersCache.expiresAt = now + ordersCacheTtlMs
  return { hit: false, orders }
}

function broadcastOrderCreated(order) {
  const payload = `event: order.created\ndata: ${JSON.stringify({ order })}\n\n`

  for (const client of orderStreamClients) {
    client.write(payload)
  }
}

function authenticateStreamToken(request, response, next) {
  const token = String(request.query?.token || '').trim()

  if (!token) {
    response.status(401).json({ error: 'Authorization token is required.' })
    return
  }

  verifyTokenIntoRequest(token, request, response, next)
}

function requireStreamToken(request, response, next) {
  if (request.user?.type !== 'orders-stream') {
    response.status(401).json({ error: 'Invalid stream token.' })
    return
  }

  next()
}

function requireJsonRequest(request, response, next) {
  if (!request.is('application/json')) {
    response.status(415).json({ error: 'Content-Type must be application/json.' })
    return
  }

  next()
}

function normalizeDesignOrderPayload(body = {}) {
  const normalizedFontId = String(body.fontId || '').trim()

  return {
    text: String(body.text || '').trim(),
    alignment: String(body.alignment || '').trim(),
    fontId: normalizedFontId,
    fontName: String(body.fontName || normalizedFontId).trim(),
    colorId: String(body.colorId || '').trim(),
    colorName: String(body.colorName || '').trim(),
    widthCm: Number(body.widthCm),
    heightCm: Number(body.heightCm),
    locationId: String(body.locationId || '').trim(),
    locationLabel: String(body.locationLabel || '').trim(),
    quotedPrice: Number(body.quotedPrice),
  }
}

function isValidDesignOrder(order) {
  return (
    order.text &&
    order.alignment &&
    order.fontId &&
    order.fontName &&
    order.colorId &&
    order.colorName &&
    order.locationId &&
    order.locationLabel &&
    Number.isFinite(order.widthCm) &&
    Number.isFinite(order.heightCm) &&
    Number.isFinite(order.quotedPrice)
  )
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
  const loginAttemptKey = getLoginAttemptKey(request, username)
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
  response.setHeader('Cache-Control', 'private, no-store')
  response.json({
    user: {
      id: Number(request.user.sub),
      username: request.user.username,
      role: request.user.role,
    },
  })
})

app.post(
  '/api/auth/stream-token',
  requireJsonRequest,
  authenticateToken,
  requireAdmin,
  (request, response) => {
    response.setHeader('Cache-Control', 'private, no-store')
    response.json({ token: createStreamToken(request.user) })
  },
)

app.get(
  '/api/design-orders',
  authenticateToken,
  requireAdmin,
  async (_request, response) => {
    try {
      await ensureOrdersTable()
      const { hit, orders } = await getCachedOrders()
      response.setHeader('Cache-Control', 'private, no-store')
      response.setHeader('X-Orders-Cache', hit ? 'HIT' : 'MISS')

      response.json({
        orders,
      })
    } catch (error) {
      console.error('Loading design orders failed:', error)
      response.status(500).json({ error: 'Unable to load design orders right now.' })
    }
  },
)

app.get(
  '/api/design-orders/stream',
  authenticateStreamToken,
  requireStreamToken,
  requireAdmin,
  (request, response) => {
    response.setHeader('Content-Type', 'text/event-stream')
    response.setHeader('Cache-Control', 'no-cache, no-transform')
    response.setHeader('Connection', 'keep-alive')
    response.flushHeaders?.()

    response.write('event: connected\ndata: {"ok":true}\n\n')
    orderStreamClients.add(response)

    const heartbeat = setInterval(() => {
      response.write(': keep-alive\n\n')
    }, 30000)

    request.on('close', () => {
      clearInterval(heartbeat)
      orderStreamClients.delete(response)
      response.end()
    })
  },
)

app.post('/api/design-orders', requireJsonRequest, async (request, response) => {
  const normalizedOrder = normalizeDesignOrderPayload(request.body)
  const designOrderClientKey = getDesignOrderClientKey(request)

  if (!designOrderClientKey) {
    response.status(400).json({ error: 'Device identification is required.' })
    return
  }

  const designOrderState = readDesignOrderAttemptState(designOrderClientKey)

  if (!isValidDesignOrder(normalizedOrder)) {
    response
      .status(400)
      .json({ error: 'Complete all four design steps before saving.' })
    return
  }

  if (designOrderState.count >= maxDesignOrdersPerDevice) {
    response.status(429).json({
      error: 'This device has reached the limit of 3 design submissions. Try again in 5 hours.',
    })
    return
  }

  try {
    await ensureOrdersTable()

    const result = await query(
      insertDesignOrderSql,
      [
        normalizedOrder.text,
        normalizedOrder.alignment,
        normalizedOrder.fontId,
        normalizedOrder.fontName,
        normalizedOrder.colorId,
        normalizedOrder.colorName,
        normalizedOrder.widthCm,
        normalizedOrder.heightCm,
        normalizedOrder.locationId,
        normalizedOrder.locationLabel,
        normalizedOrder.quotedPrice,
      ],
    )

    const savedOrder = {
      id: result.rows[0].id,
      ...normalizedOrder,
      submittedAt: result.rows[0].submitted_at,
    }

    registerDesignOrderAttempt(designOrderClientKey)
    invalidateOrdersCache()
    broadcastOrderCreated(savedOrder)

    response.status(201).json({
      id: savedOrder.id,
      submittedAt: savedOrder.submittedAt,
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
