const express = require('express');
const { createDDoSProtection } = require('../middleware/ddosProtection');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

// Create Express app
const app = express();

// Middleware
app.use(helmet()); // Security headers
app.use(cors()); // Cross-origin resource sharing
app.use(express.json({ limit: '10mb' })); // Parse JSON bodies
app.use(express.urlencoded({ extended: true, limit: '10mb' })); // Parse URL-encoded bodies

// Create DDoS protection middleware with custom options
const ddosProtection = createDDoSProtection({
  // Rate limiting
  maxRequestsPerMinute: 60,
  maxRequestsPerHour: 1000,
  maxRequestsPerDay: 5000,
  
  // Burst protection
  burstThreshold: 10,
  burstWindow: 1000,
  
  // IP blocking
  blockDuration: 3600000, // 1 hour
  maxFailedAttempts: 5,
  
  // Geographic filtering
  blockedCountries: ['CN', 'RU'],
  allowedCountries: [], // If empty, all countries except blocked are allowed
  
  // User agent filtering
  blockedUserAgents: ['masscan', 'nmap', 'sqlmap'],
  suspiciousUserAgents: ['curl', 'wget'],
  
  // Request size limits
  maxRequestSize: '10mb',
  maxURILength: 2048,
  
  // Connection limits
  maxConnectionsPerIP: 10,
  
  // Redis configuration
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD || null
  },
  
  // Logging
  logLevel: 'info',
  logToFile: true,
  logFilePath: './logs/ddos-protection.log',
  
  // Whitelisting
  whitelistedIPs: ['127.0.0.1', '::1'],
  whitelistedUserAgents: ['Googlebot', 'Bingbot'],
  
  // Advanced detection
  enableHeuristicAnalysis: true,
  enableBehavioralAnalysis: true,
  
  // Response settings
  blockResponseCode: 429,
  blockMessage: 'Too Many Requests - DDoS Protection Activated'
});

// Apply DDoS protection middleware to all routes
app.use(ddosProtection);

// Routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Hello World!', 
    timestamp: new Date().toISOString(),
    clientIP: req.ip
  });
});

app.get('/api/status', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString()
  });
});

app.post('/api/data', (req, res) => {
  res.json({ 
    message: 'Data received', 
    data: req.body,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/users/:id', (req, res) => {
  res.json({ 
    id: req.params.id,
    name: `User ${req.params.id}`,
    timestamp: new Date().toISOString()
  });
});

// Admin routes (example)
app.get('/admin/dashboard', (req, res) => {
  res.json({ 
    message: 'Admin Dashboard', 
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not Found',
    timestamp: new Date().toISOString()
  });
});

// Start server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
  });
});

module.exports = app;
