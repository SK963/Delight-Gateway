const express = require('express');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const axios = require('axios');
const winston = require('winston');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const path = require('path');
require('dotenv').config();

// ── Logger ──────────────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'api-gateway' },
  transports: [new winston.transports.Console()]
});

// ── Express App ─────────────────────────────────────────────────────────────
const app = express();
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// ── Swagger UI ──────────────────────────────────────────────────────────────
const swaggerDoc = YAML.load(path.join(__dirname, 'openapi.yaml'));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDoc, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Cake Delight API – Swagger Docs'
}));

// ── Service URLs ────────────────────────────────────────────────────────────
const CATALOG_URL      = process.env.CATALOG_URL      || 'http://catalog-service:3001';
const ORDER_URL        = process.env.ORDER_URL         || 'http://order-service:3002';
const RATING_URL       = process.env.RATING_URL        || 'http://rating-service:3003';
const NOTIFICATION_URL = process.env.NOTIFICATION_URL  || 'http://notification-service:3004';
const JWT_SECRET       = process.env.JWT_SECRET        || 'cake-delight-secret-key-change-me';
const JWT_EXPIRES_IN   = process.env.JWT_EXPIRES_IN    || '24h';

// ── User Model ──────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 6 },
    name:     { type: String, required: true, trim: true },
    role:     { type: String, enum: ['admin', 'customer'], default: 'customer' }
  },
  { timestamps: true }
);

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

// Remove password from JSON output
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

const User = mongoose.model('User', userSchema);

// ── JWT Helpers ─────────────────────────────────────────────────────────────
function signToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

// ── Auth Middleware ──────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: { code: 'UNAUTHORIZED', message: 'Missing or invalid Authorization header. Use: Bearer <token>' }
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    req.headers['x-customer-id'] = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({
      error: { code: 'INVALID_TOKEN', message: 'Token is invalid or expired' }
    });
  }
}

// Optional Auth
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      req.headers['x-customer-id'] = decoded.id;
    } catch {}
  }
  next();
}

// ── Admin Middleware ─────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      error: { code: 'FORBIDDEN', message: 'Admin access required' }
    });
  }
  next();
}

// ── Public Routes ───────────────────────────────────────────────────────────

// Health
app.get('/health', async (_req, res) => {
  const services = [
    { name: 'catalog-service',      url: `${CATALOG_URL}/health` },
    { name: 'order-service',        url: `${ORDER_URL}/health` },
    { name: 'rating-service',       url: `${RATING_URL}/health` },
    { name: 'notification-service', url: `${NOTIFICATION_URL}/health` }
  ];

  const results = await Promise.allSettled(
    services.map(async (s) => {
      try {
        const { data } = await axios.get(s.url, { timeout: 3000 });
        return { name: s.name, status: 'ok', details: data };
      } catch (err) {
        return { name: s.name, status: 'down', error: err.message };
      }
    })
  );

  const report = results.map((r) => r.value || r.reason);
  const allUp = report.every((r) => r.status === 'ok');

  res.status(allUp ? 200 : 503).json({
    service: 'api-gateway',
    status: allUp ? 'ok' : 'degraded',
    uptime: process.uptime(),
    services: report
  });
});

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'email, password, and name are required' }
      });
    }
    if (password.length < 6) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'Password must be at least 6 characters' }
      });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({
        error: { code: 'EMAIL_EXISTS', message: 'An account with this email already exists' }
      });
    }

    const user = await User.create({ email, password, name, role: 'customer' });
    const token = signToken(user);

    logger.info('User registered', { userId: user._id, email: user.email, role: user.role });
    res.status(201).json({ token, user: user.toJSON() });
  } catch (err) {
    logger.error('Registration error', { error: err.message });
    res.status(500).json({ error: { code: 'AUTH_ERROR', message: err.message } });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: { code: 'VALIDATION_ERROR', message: 'email and password are required' }
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' }
      });
    }

    const token = signToken(user);
    logger.info('User logged in', { userId: user._id, email: user.email, role: user.role });
    res.json({ token, user: user.toJSON() });
  } catch (err) {
    logger.error('Login error', { error: err.message });
    res.status(500).json({ error: { code: 'AUTH_ERROR', message: err.message } });
  }
});

// Current user profile
app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name, role: req.user.role });
});

// ── Proxy Middleware Factory ────────────────────────────────────────────────
function makeProxy(target, name) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    pathRewrite: (_path, req) => req.originalUrl,
    on: {
      proxyReq: (proxyReq, req, res) => {
        if (req.user) {
          proxyReq.setHeader('x-customer-id', req.user.id);
        }
        fixRequestBody(proxyReq, req);
        logger.info('Proxying request', {
          method: req.method,
          path: req.originalUrl,
          target: name,
          userId: req.user?.id
        });
      },
      error: (err, req, res) => {
        logger.error('Proxy error', {
          target: name,
          path: req.originalUrl,
          error: err.message
        });
        if (!res.headersSent) {
          res.status(502).json({
            error: {
              code: 'GATEWAY_ERROR',
              message: `Service ${name} is unavailable`,
              details: err.message
            }
          });
        }
      }
    }
  });
}

// ── Uploads Static Files Proxy ──────────────────────────────────────────────
app.use('/uploads', makeProxy(CATALOG_URL, 'catalog-service'));

// ── Admin-Only Catalog Routes ────────────────────────────────────────────────
const catalogProxy = makeProxy(CATALOG_URL, 'catalog-service');
app.patch('/api/cakes/:id/stock', authenticate, requireAdmin, catalogProxy);
app.delete('/api/cakes/:id', authenticate, requireAdmin, catalogProxy);
app.put('/api/cakes/:id', authenticate, requireAdmin, catalogProxy);
app.post('/api/cakes', authenticate, requireAdmin, catalogProxy);

// ── Ratings Proxy (intercept all routes containing /ratings) ────────────────
const ratingProxy = makeProxy(RATING_URL, 'rating-service');
app.use((req, res, next) => {
  if (req.originalUrl.includes('/ratings')) {
    return optionalAuth(req, res, () => ratingProxy(req, res, next));
  }
  next();
});

// ── Order & Basket Proxy ────────────────────────────────────────────────────
const orderProxy = makeProxy(ORDER_URL, 'order-service');
app.use('/api/basket', authenticate, orderProxy);
app.use('/api/orders', authenticate, orderProxy);

// ── Notification Proxy ──────────────────────────────────────────────────────
app.use('/api/notifications', authenticate, makeProxy(NOTIFICATION_URL, 'notification-service'));

// ── Catalog Read Proxy ──────────────────────────────────────────────────────
app.get('/api/cakes', optionalAuth, catalogProxy);
app.get('/api/cakes/:id', optionalAuth, catalogProxy);

// ── 404 handler ─────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({
    error: { code: 'NOT_FOUND', message: 'Route not found' }
  });
});

// ── Seed Admin User ─────────────────────────────────────────────────────────
async function seedAdmin() {
  const adminEmail = 'admin@cakedelight.com';
  const existing = await User.findOne({ email: adminEmail });
  if (!existing) {
    await User.create({
      email: adminEmail,
      password: 'admin123',
      name: 'Admin',
      role: 'admin'
    });
    logger.info('Seeded admin user', { email: adminEmail, password: 'admin123' });
  }
}

// ── Start Server ────────────────────────────────────────────────────────────
async function start() {
  await mongoose.connect(process.env.MONGO_URI || 'mongodb://mongo:27017/gateway-db');
  logger.info('Connected to MongoDB (user store)');

  await seedAdmin();

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    logger.info(`api-gateway ready on port ${PORT}`);
    logger.info('Swagger UI available at /api-docs');
    logger.info('Admin: admin@cakedelight.com / admin123');
  });
}

start().catch((err) => {
  logger.error('Failed to start api-gateway', { error: err.message });
  process.exit(1);
});
