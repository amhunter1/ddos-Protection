const redis = require('ioredis');
const ipRangeCheck = require('ip-range-check');
const userAgents = require('user-agents');
const geoip = require('geoip-lite');
const { v4: uuidv4 } = require('uuid');
const moment = require('moment');
const fs = require('fs').promises;
const path = require('path');

class DDoSProtection {
  constructor(options = {}) {
    this.validateOptions(options);
    this.options = {
      // Rate limiting
      maxRequestsPerMinute: options.maxRequestsPerMinute || 100,
      maxRequestsPerHour: options.maxRequestsPerHour || 1000,
      maxRequestsPerDay: options.maxRequestsPerDay || 5000,

      // Burst protection
      burstThreshold: options.burstThreshold || 20,
      burstWindow: options.burstWindow || 1000, // milliseconds

      // IP blocking
      blockDuration: options.blockDuration || 3600000, // 1 hour in milliseconds
      maxFailedAttempts: options.maxFailedAttempts || 5,

      // Geographic filtering
      blockedCountries: options.blockedCountries || [],
      allowedCountries: options.allowedCountries || [],

      // User agent filtering
      blockedUserAgents: options.blockedUserAgents || [],
      suspiciousUserAgents: options.suspiciousUserAgents || [],

      // Request size limits
      maxRequestSize: options.maxRequestSize || '10mb',
      maxURILength: options.maxURILength || 2048,

      // Connection limits
      maxConnectionsPerIP: options.maxConnectionsPerIP || 20,

      // Redis configuration
      redis: options.redis || {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD || null
      },

      // Logging
      logLevel: options.logLevel || 'info',
      logToFile: options.logToFile || false,
      logFilePath: options.logFilePath || './logs/ddos-protection.log',

      // Whitelisting
      whitelistedIPs: options.whitelistedIPs || [],
      whitelistedUserAgents: options.whitelistedUserAgents || [],

      // Challenge mechanisms
      enableCaptcha: options.enableCaptcha || false,
      enableJSChallenge: options.enableJSChallenge || false,

      // Advanced detection
      enableHeuristicAnalysis: options.enableHeuristicAnalysis || true,
      enableBehavioralAnalysis: options.enableBehavioralAnalysis || true,

      // Response settings
      blockResponseCode: options.blockResponseCode || 429,
      blockMessage: options.blockMessage || 'Too Many Requests',

      // Cleanup settings
      cleanupInterval: options.cleanupInterval || 300000, // 5 minutes
      dataRetention: options.dataRetention || 86400000 // 24 hours
    };

    this.redisClient = null;
    this.redisAvailable = false;
    this.initializeRedis();
    this.requestCounts = new Map();
    this.blockedIPs = new Map();
    this.connectionCounts = new Map();
    this.userAgentStats = new Map();
    this.geoStats = new Map();
    this.suspiciousActivities = new Map();
    this.initializeLogging();
    this.startCleanupInterval();
    this.loadConfiguration();
  }

  validateOptions(options) {
    const numericOptions = [
      'maxRequestsPerMinute', 'maxRequestsPerHour', 'maxRequestsPerDay',
      'burstThreshold', 'burstWindow', 'blockDuration', 'maxFailedAttempts',
      'maxURILength', 'maxConnectionsPerIP', 'blockResponseCode',
      'cleanupInterval', 'dataRetention'
    ];
    for (const option of numericOptions) {
      if (options[option] !== undefined && (typeof options[option] !== 'number' || options[option] < 0)) {
        throw new Error(`Invalid ${option}: must be a positive number`);
      }
    }
    const arrayOptions = [
      'blockedCountries', 'allowedCountries', 'blockedUserAgents',
      'suspiciousUserAgents', 'whitelistedIPs', 'whitelistedUserAgents'
    ];

    for (const option of arrayOptions) {
      if (options[option] !== undefined && !Array.isArray(options[option])) {
        throw new Error(`Invalid ${option}: must be an array`);
      }
    }
    const stringOptions = ['maxRequestSize', 'logLevel', 'logFilePath', 'blockMessage'];

    for (const option of stringOptions) {
      if (options[option] !== undefined && typeof options[option] !== 'string') {
        throw new Error(`Invalid ${option}: must be a string`);
      }
    }
    if (options.logLevel && !['debug', 'info', 'warn', 'error'].includes(options.logLevel)) {
      throw new Error('Invalid logLevel: must be one of debug, info, warn, error');
    }
    const booleanOptions = [
      'logToFile', 'enableCaptcha', 'enableJSChallenge',
      'enableHeuristicAnalysis', 'enableBehavioralAnalysis'
    ];

    for (const option of booleanOptions) {
      if (options[option] !== undefined && typeof options[option] !== 'boolean') {
        throw new Error(`Invalid ${option}: must be a boolean`);
      }
    }
    if (options.redis) {
      if (typeof options.redis !== 'object') {
        throw new Error('Invalid redis: must be an object');
      }

      if (options.redis.host && typeof options.redis.host !== 'string') {
        throw new Error('Invalid redis.host: must be a string');
      }

      if (options.redis.port && (typeof options.redis.port !== 'number' || options.redis.port < 1 || options.redis.port > 65535)) {
        throw new Error('Invalid redis.port: must be a number between 1 and 65535');
      }

      if (options.redis.password && typeof options.redis.password !== 'string') {
        throw new Error('Invalid redis.password: must be a string');
      }
    }

    if (options.maxRequestSize) {
      const sizeRegex = /^(\d+)([a-z]+)$/i;
      if (!sizeRegex.test(options.maxRequestSize)) {
        throw new Error('Invalid maxRequestSize: must be in format like "10mb", "5kb", etc.');
      }
    }

    if (options.blockedCountries) {
      for (const country of options.blockedCountries) {
        if (typeof country !== 'string' || country.length !== 2) {
          throw new Error('Invalid blockedCountries: all entries must be 2-letter country codes');
        }
      }
    }

    if (options.allowedCountries) {
      for (const country of options.allowedCountries) {
        if (typeof country !== 'string' || country.length !== 2) {
          throw new Error('Invalid allowedCountries: all entries must be 2-letter country codes');
        }
      }
    }
  }

  async initializeRedis() {
    try {
      this.redisClient = new redis(this.options.redis);

      this.redisClient.on('error', (error) => {
        this.log('warn', `Redis connection error: ${error.message}`);
        this.redisAvailable = false;
      });

      this.redisClient.on('connect', () => {
        this.log('info', 'Redis connected successfully');
        this.redisAvailable = true;
      });

      this.redisClient.on('ready', () => {
        this.log('info', 'Redis is ready');
        this.redisAvailable = true;
      });

      this.redisClient.on('close', () => {
        this.log('warn', 'Redis connection closed');
        this.redisAvailable = false;
      });

      // Test connection
      await this.redisClient.ping();
      this.redisAvailable = true;
      this.log('info', 'Redis initialized successfully');
    } catch (error) {
      this.log('error', `Failed to initialize Redis: ${error.message}`);
      this.redisAvailable = false;
      this.redisClient = null;
    }
  }

  // Safe Redis operation wrapper
  async safeRedisOperation(operation, fallback = null) {
    if (!this.redisAvailable || !this.redisClient) {
      return fallback ? fallback() : null;
    }

    try {
      return await operation();
    } catch (error) {
      this.log('warn', `Redis operation failed: ${error.message}`);
      this.redisAvailable = false;
      return fallback ? fallback() : null;
    }
  }

  async initializeLogging() {
    if (this.options.logToFile) {
      try {
        const logDir = path.dirname(this.options.logFilePath);
        await fs.mkdir(logDir, { recursive: true });
      } catch (error) {
        console.error('Failed to create logs directory:', error);
      }
    }
  }

  // Load configuration from files
  async loadConfiguration() {
    try {
      // Load IP whitelist
      const whitelistPath = path.join(__dirname, '../config/whitelist.json');
      const whitelistData = await fs.readFile(whitelistPath, 'utf8');
      const whitelist = JSON.parse(whitelistData);
      
      if (whitelist.ips) {
        this.options.whitelistedIPs = [...this.options.whitelistedIPs, ...whitelist.ips];
      }
      
      if (whitelist.userAgents) {
        this.options.whitelistedUserAgents = [...this.options.whitelistedUserAgents, ...whitelist.userAgents];
      }
      
      // Load blocked lists
      const blocklistPath = path.join(__dirname, '../config/blocklist.json');
      const blocklistData = await fs.readFile(blocklistPath, 'utf8');
      const blocklist = JSON.parse(blocklistData);
      
      if (blocklist.countries) {
        this.options.blockedCountries = [...this.options.blockedCountries, ...blocklist.countries];
      }
      
      if (blocklist.userAgents) {
        this.options.blockedUserAgents = [...this.options.blockedUserAgents, ...blocklist.userAgents];
      }
      
      this.log('info', 'Configuration loaded successfully');
    } catch (error) {
      this.log('warn', 'Failed to load configuration files:', error.message);
    }
  }

  async middleware(req, res, next) {
    const clientIP = this.getClientIP(req);
    const userAgent = req.get('User-Agent') || '';
    const method = req.method;
    const url = req.url;
    const timestamp = Date.now();
    
    // Generate unique request ID
    const requestId = uuidv4();
    
    try {
      // Check if IP is whitelisted
      if (this.isWhitelisted(clientIP, userAgent)) {
        this.log('debug', `Whitelisted request from ${clientIP}`, { requestId, clientIP, userAgent });
        return next();
      }
      
      // Check if IP is blocked
      if (await this.isBlocked(clientIP)) {
        this.log('warn', `Blocked request from ${clientIP} (already blocked)`, { requestId, clientIP });
        return this.sendBlockResponse(res, 'IP_BLOCKED');
      }
      
      // Validate request
      const validation = this.validateRequest(req);
      if (!validation.valid) {
        this.log('warn', `Invalid request from ${clientIP}: ${validation.reason}`, { 
          requestId, 
          clientIP, 
          reason: validation.reason 
        });
        return this.sendBlockResponse(res, validation.reason);
      }
      
      const geoCheck = this.checkGeographicRestrictions(clientIP);
      if (!geoCheck.allowed) {
        this.log('warn', `Geographic restriction for ${clientIP}: ${geoCheck.reason}`, { 
          requestId, 
          clientIP, 
          country: geoCheck.country 
        });
        return this.sendBlockResponse(res, geoCheck.reason);
      }
      
      const userAgentCheck = this.checkUserAgent(userAgent);
      if (!userAgentCheck.allowed) {
        this.log('warn', `Blocked user agent from ${clientIP}: ${userAgent}`, { 
          requestId, 
          clientIP, 
          userAgent 
        });
        return this.sendBlockResponse(res, userAgentCheck.reason);
      }
      const connectionCheck = await this.updateConnectionCount(clientIP);
      if (!connectionCheck.allowed) {
        this.log('warn', `Too many connections from ${clientIP}`, { 
          requestId, 
          clientIP, 
          connections: connectionCheck.count 
        });
        return this.sendBlockResponse(res, 'TOO_MANY_CONNECTIONS');
      }
      const rateCheck = await this.updateRequestCounts(clientIP, timestamp);
      if (!rateCheck.allowed) {
        this.log('warn', `Rate limit exceeded for ${clientIP}`, { 
          requestId, 
          clientIP, 
          window: rateCheck.window 
        });
        return this.sendBlockResponse(res, 'RATE_LIMIT_EXCEEDED');
      }
      if (this.options.enableHeuristicAnalysis) {
        const heuristicCheck = this.performHeuristicAnalysis(req, clientIP);
        if (!heuristicCheck.allowed) {
          this.log('warn', `Suspicious activity detected from ${clientIP}: ${heuristicCheck.reason}`, { 
            requestId, 
            clientIP, 
            reason: heuristicCheck.reason 
          });
          return this.sendBlockResponse(res, heuristicCheck.reason);
        }
      }
      
      if (this.options.enableBehavioralAnalysis) {
        const behaviorCheck = await this.performBehavioralAnalysis(clientIP, req);
        if (!behaviorCheck.allowed) {
          this.log('warn', `Abnormal behavior detected from ${clientIP}: ${behaviorCheck.reason}`, { 
            requestId, 
            clientIP, 
            reason: behaviorCheck.reason 
          });
          return this.sendBlockResponse(res, behaviorCheck.reason);
        }
      }
      
      this.log('debug', `Allowed request from ${clientIP}`, { requestId, clientIP, method, url });
      this.addSecurityHeaders(res);
      next();
    } catch (error) {
      this.log('error', `Error processing request from ${clientIP}: ${error.message}`, { 
        requestId, 
        clientIP, 
        error: error.stack 
      });
      next();
    }
  }

  // Get client IP address
  getClientIP(req) {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           req.headers['x-forwarded-for'] ||
           req.headers['x-real-ip'] ||
           'unknown';
  }

  // Check if IP or user agent is whitelisted
  isWhitelisted(ip, userAgent) {
    // Check IP whitelist
    if (this.options.whitelistedIPs.includes(ip)) {
      return true;
    }
    
    // Check user agent whitelist
    if (this.options.whitelistedUserAgents.some(ua => userAgent.includes(ua))) {
      return true;
    }
    
    return false;
  }

  // Check if IP is blocked
  async isBlocked(ip) {
    // Check in-memory blocked IPs
    if (this.blockedIPs.has(ip)) {
      const blockInfo = this.blockedIPs.get(ip);
      if (Date.now() < blockInfo.expires) {
        return true;
      } else {
        // Block expired, remove it
        this.blockedIPs.delete(ip);
        await this.safeRedisOperation(() => this.redisClient.del(`blocked:${ip}`));
      }
    }

    // Check Redis for blocked IPs
    const blocked = await this.safeRedisOperation(
      () => this.redisClient.get(`blocked:${ip}`),
      () => null
    );

    if (blocked) {
      const blockInfo = JSON.parse(blocked);
      if (Date.now() < blockInfo.expires) {
        this.blockedIPs.set(ip, blockInfo);
        return true;
      } else {
        await this.safeRedisOperation(() => this.redisClient.del(`blocked:${ip}`));
      }
    }

    return false;
  }

  validateRequest(req) {
    if (req.url.length > this.options.maxURILength) {
      return { 
        valid: false, 
        reason: 'URI_TOO_LONG' 
      };
    }
    const contentLength = req.headers['content-length'];
    if (contentLength) {
      const maxSizeBytes = this.parseSize(this.options.maxRequestSize);
      if (parseInt(contentLength) > maxSizeBytes) {
        return { 
          valid: false, 
          reason: 'REQUEST_TOO_LARGE' 
        };
      }
    }
    
    const suspiciousHeaders = [
      'x-forwarded-for',
      'x-original-host',
      'x-rewrite-url',
      'x-original-url'
    ];
    
    for (const header of suspiciousHeaders) {
      if (req.headers[header] && req.headers[header].includes('://')) {
        return { 
          valid: false, 
          reason: 'SUSPICIOUS_HEADER' 
        };
      }
    }
    
    return { valid: true };
  }

  parseSize(sizeStr) {
    const units = {
      'b': 1,
      'kb': 1024,
      'mb': 1024 * 1024,
      'gb': 1024 * 1024 * 1024
    };
    
    const match = sizeStr.match(/^(\d+)([a-z]+)$/i);
    if (match) {
      const value = parseInt(match[1]);
      const unit = match[2].toLowerCase();
      return value * (units[unit] || 1);
    }
    
    return parseInt(sizeStr) || 0;
  }

  checkGeographicRestrictions(ip) {
    try {
      const geo = geoip.lookup(ip);
      if (!geo) {
        return { allowed: true };
      }
      
      const country = geo.country;
      
      // Check blocked countries
      if (this.options.blockedCountries.includes(country)) {
        return { 
          allowed: false, 
          reason: 'COUNTRY_BLOCKED', 
          country 
        };
      }
      
      // Check allowed countries (if specified)
      if (this.options.allowedCountries.length > 0 && 
          !this.options.allowedCountries.includes(country)) {
        return { 
          allowed: false, 
          reason: 'COUNTRY_NOT_ALLOWED', 
          country 
        };
      }
      
      if (!this.geoStats.has(country)) {
        this.geoStats.set(country, { requests: 0, blocked: 0 });
      }
      const stats = this.geoStats.get(country);
      stats.requests++;
      
      return { allowed: true, country };
    } catch (error) {
      this.log('error', `Geo lookup failed for ${ip}: ${error.message}`);
      return { allowed: true };
    }
  }

  checkUserAgent(userAgent) {
    // Check blocked user agents
    if (this.options.blockedUserAgents.some(bua => userAgent.includes(bua))) {
      return { 
        allowed: false, 
        reason: 'USER_AGENT_BLOCKED' 
      };
    }
    
    // Check suspicious user agents
    if (this.options.suspiciousUserAgents.some(sua => userAgent.includes(sua))) {
      return { 
        allowed: false, 
        reason: 'SUSPICIOUS_USER_AGENT' 
      };
    }
    
    if (!this.userAgentStats.has(userAgent)) {
      this.userAgentStats.set(userAgent, { requests: 0, blocked: 0 });
    }
    const stats = this.userAgentStats.get(userAgent);
    stats.requests++;
    
    return { allowed: true };
  }

  async updateConnectionCount(ip) {
    let count = this.connectionCounts.get(ip) || 0;
    count++;
    this.connectionCounts.set(ip, count);
    const redisKey = `connections:${ip}`;
    const redisCount = await this.safeRedisOperation(
      async () => {
        const count = await this.redisClient.incr(redisKey);
        await this.redisClient.expire(redisKey, 300); // Expire in 5 minutes
        return count;
      },
      () => count
    );

    // Check if over limit
    if (count > this.options.maxConnectionsPerIP ||
        redisCount > this.options.maxConnectionsPerIP) {
      // Block the IP
      await this.blockIP(ip, 'TOO_MANY_CONNECTIONS');
      return { allowed: false, count: Math.max(count, redisCount) };
    }

    return { allowed: true, count: Math.max(count, redisCount) };
  }

  // Update request counts
  async updateRequestCounts(ip, timestamp) {
    const now = Date.now();
    const minuteKey = `requests:${ip}:minute:${Math.floor(now / 60000)}`;
    const hourKey = `requests:${ip}:hour:${Math.floor(now / 3600000)}`;
    const dayKey = `requests:${ip}:day:${Math.floor(now / 86400000)}`;

    const [minuteCount, hourCount, dayCount] = await this.safeRedisOperation(
      async () => {
        const [min, hour, day] = await Promise.all([
          this.redisClient.incr(minuteKey),
          this.redisClient.incr(hourKey),
          this.redisClient.incr(dayKey)
        ]);
        await Promise.all([
          this.redisClient.expire(minuteKey, 120), // 2 minutes
          this.redisClient.expire(hourKey, 3900),  // 65 minutes
          this.redisClient.expire(dayKey, 90000)   // 25 hours
        ]);

        return [min, hour, day];
      },
      () => [1, 1, 1] // Fallback to 1 if Redis is unavailable
    );

    // Check rate limits
    if (minuteCount > this.options.maxRequestsPerMinute) {
      await this.blockIP(ip, 'RATE_LIMIT_EXCEEDED_MINUTE');
      return { allowed: false, window: 'minute', count: minuteCount };
    }

    if (hourCount > this.options.maxRequestsPerHour) {
      await this.blockIP(ip, 'RATE_LIMIT_EXCEEDED_HOUR');
      return { allowed: false, window: 'hour', count: hourCount };
    }

    if (dayCount > this.options.maxRequestsPerDay) {
      await this.blockIP(ip, 'RATE_LIMIT_EXCEEDED_DAY');
      return { allowed: false, window: 'day', count: dayCount };
    }

    return { allowed: true };
  }

  // Perform heuristic analysis
  performHeuristicAnalysis(req, ip) {
    const userAgent = req.get('User-Agent') || '';
    const acceptHeader = req.get('Accept') || '';
    const acceptEncoding = req.get('Accept-Encoding') || '';
    const acceptLanguage = req.get('Accept-Language') || '';
    
    const requiredHeaders = ['accept', 'accept-encoding', 'accept-language'];
    let missingHeaders = 0;
    
    if (!acceptHeader) missingHeaders++;
    if (!acceptEncoding) missingHeaders++;
    if (!acceptLanguage) missingHeaders++;
    
    if (missingHeaders >= 2) {
      this.incrementSuspiciousActivity(ip, 'MISSING_HEADERS');
      return { allowed: false, reason: 'MISSING_REQUIRED_HEADERS' };
    }
    
    const suspiciousPatterns = [
      /(\.php|\.asp|\.jsp)/i,
      /(\.\.\/)/,
      /(union|select|insert|delete|update|drop|create|alter)/i
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(req.url)) {
        this.incrementSuspiciousActivity(ip, 'SUSPICIOUS_URL_PATTERN');
        return { allowed: false, reason: 'SUSPICIOUS_URL_PATTERN' };
      }
    }
    
    // Check for too many parameters
    const paramCount = Object.keys(req.query).length + Object.keys(req.body).length;
    if (paramCount > 50) {
      this.incrementSuspiciousActivity(ip, 'TOO_MANY_PARAMETERS');
      return { allowed: false, reason: 'TOO_MANY_PARAMETERS' };
    }
    
    return { allowed: true };
  }

  async performBehavioralAnalysis(ip, req) {
    const now = Date.now();
    const key = `behavior:${ip}`;
    const timestamps = await this.safeRedisOperation(
      () => this.redisClient.lrange(key, 0, 99),
      () => []
    );
    const timestampsMs = timestamps.map(ts => parseInt(ts));
    await this.safeRedisOperation(
      async () => {
        await this.redisClient.lpush(key, now);
        await this.redisClient.ltrim(key, 0, 99);
        await this.redisClient.expire(key, 3600);
      },
      () => {}
    );
    if (timestampsMs.length >= 10) {
      const recentTimestamps = timestampsMs.slice(0, 10);
      const timeDiff = recentTimestamps[0] - recentTimestamps[9];

      if (timeDiff < this.options.burstWindow) {
        const requestsPerSecond = 10000 / timeDiff;
        if (requestsPerSecond > this.options.burstThreshold) {
          await this.blockIP(ip, 'BURST_ACTIVITY');
          return { allowed: false, reason: 'BURST_ACTIVITY_DETECTED' };
        }
      }
    }

    return { allowed: true };
  }
  incrementSuspiciousActivity(ip, reason) {
    if (!this.suspiciousActivities.has(ip)) {
      this.suspiciousActivities.set(ip, new Map());
    }
    
    const ipActivities = this.suspiciousActivities.get(ip);
    const count = ipActivities.get(reason) || 0;
    ipActivities.set(reason, count + 1);
    const totalCount = Array.from(ipActivities.values()).reduce((sum, val) => sum + val, 0);
    if (totalCount > this.options.maxFailedAttempts) {
      this.blockIP(ip, 'TOO_MANY_SUSPICIOUS_ACTIVITIES');
    }
  }
  async blockIP(ip, reason) {
    const expires = Date.now() + this.options.blockDuration;
    const blockInfo = {
      ip,
      reason,
      timestamp: Date.now(),
      expires
    };
    this.blockedIPs.set(ip, blockInfo);
    await this.safeRedisOperation(
      () => this.redisClient.setex(
        `blocked:${ip}`,
        Math.ceil(this.options.blockDuration / 1000),
        JSON.stringify(blockInfo)
      ),
      () => {}
    );
    try {
      const geo = geoip.lookup(ip);
      if (geo && this.geoStats.has(geo.country)) {
        const stats = this.geoStats.get(geo.country);
        stats.blocked++;
      }
    } catch (error) {
    }

    this.log('info', `Blocked IP ${ip} for reason: ${reason}`, { ip, reason });
  }

  sendBlockResponse(res, reason) {
    res.status(this.options.blockResponseCode).json({
      error: this.options.blockMessage,
      reason: reason,
      timestamp: new Date().toISOString()
    });
  }
  addSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
  }
  log(level, message, data = {}) {
    if (this.shouldLog(level)) {
      const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        data
      };
      console.log(`[${level.toUpperCase()}] ${message}`, data);
      if (this.options.logToFile) {
        this.writeToFile(logEntry);
      }
    }
  }
  shouldLog(level) {
    const levels = ['debug', 'info', 'warn', 'error'];
    const currentLevelIndex = levels.indexOf(this.options.logLevel);
    const messageLevelIndex = levels.indexOf(level);

    return messageLevelIndex >= currentLevelIndex;
  }
  async writeToFile(logEntry) {
    try {
      const logLine = JSON.stringify(logEntry) + '\n';
      await fs.appendFile(this.options.logFilePath, logLine);
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }
  }
  startCleanupInterval() {
    setInterval(() => {
      const now = Date.now();
      for (const [ip, blockInfo] of this.blockedIPs.entries()) {
        if (now > blockInfo.expires) {
          this.blockedIPs.delete(ip);
        }
      }
      for (const [ip, count] of this.connectionCounts.entries()) {
        if (count <= 0) {
          this.connectionCounts.delete(ip);
        }
      }
      for (const [ip, activities] of this.suspiciousActivities.entries()) {
        let totalCount = 0;
        for (const [reason, count] of activities.entries()) {
          totalCount += count;
        }
        if (totalCount <= 0) {
          this.suspiciousActivities.delete(ip);
        }
      }
    }, this.options.cleanupInterval);
  }

  // Get statistics
  async getStats() {
    const [blockedCount, connectionCount, requestCount] = await Promise.all([
      this.safeRedisOperation(() => this.redisClient.keys('blocked:*'), () => []),
      this.safeRedisOperation(() => this.redisClient.keys('connections:*'), () => []),
      this.safeRedisOperation(() => this.redisClient.keys('requests:*'), () => [])
    ]);

    return {
      blockedIPs: blockedCount.length,
      activeConnections: connectionCount.length,
      totalRequests: requestCount.length,
      inMemoryBlocked: this.blockedIPs.size,
      inMemoryConnections: this.connectionCounts.size,
      suspiciousActivities: this.suspiciousActivities.size,
      userAgentStats: this.userAgentStats.size,
      geoStats: this.geoStats.size,
      redisAvailable: this.redisAvailable
    };
  }

  // Get blocked IPs
  async getBlockedIPs() {
    const keys = await this.safeRedisOperation(
      () => this.redisClient.keys('blocked:*'),
      () => []
    );
    const blocked = [];

    for (const key of keys) {
      const data = await this.safeRedisOperation(
        () => this.redisClient.get(key),
        () => null
      );
      if (data) {
        blocked.push(JSON.parse(data));
      }
    }
    for (const [ip, blockInfo] of this.blockedIPs.entries()) {
      if (!blocked.some(b => b.ip === ip)) {
        blocked.push(blockInfo);
      }
    }

    return blocked;
  }

  // Unblock an IP
  async unblockIP(ip) {
    this.blockedIPs.delete(ip);
    await this.safeRedisOperation(
      () => this.redisClient.del(`blocked:${ip}`),
      () => {}
    );
    this.log('info', `Unblocked IP ${ip}`);
  }

  // Close connections
  async close() {
    if (this.redisClient) {
      await this.safeRedisOperation(
        () => this.redisClient.quit(),
        () => {}
      );
    }
  }
}
const createDDoSProtection = (options) => {
  const protection = new DDoSProtection(options);
  
  return async (req, res, next) => {
    await protection.middleware(req, res, next);
  };
};
module.exports = {
  DDoSProtection,
  createDDoSProtection
};

