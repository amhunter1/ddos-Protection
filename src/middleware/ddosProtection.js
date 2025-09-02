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
    // Validate configuration options
    this.validateOptions(options);

    // Configuration options with defaults
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

    // Initialize Redis client with error handling
    this.redisClient = null;
    this.redisAvailable = false;
    this.initializeRedis();
    
    // Initialize data structures
    this.requestCounts = new Map();
    this.blockedIPs = new Map();
    this.connectionCounts = new Map();
    this.userAgentStats = new Map();
    this.geoStats = new Map();
    this.suspiciousActivities = new Map();
    
    // Initialize logging
    this.initializeLogging();
    
    // Start cleanup interval
    this.startCleanupInterval();
    
    // Load configuration files if they exist
    this.loadConfiguration();
  }

  // Validate configuration options
  validateOptions(options) {
    // Validate numeric options
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

    // Validate array options
    const arrayOptions = [
      'blockedCountries', 'allowedCountries', 'blockedUserAgents',
      'suspiciousUserAgents', 'whitelistedIPs', 'whitelistedUserAgents'
    ];

    for (const option of arrayOptions) {
      if (options[option] !== undefined && !Array.isArray(options[option])) {
        throw new Error(`Invalid ${option}: must be an array`);
      }
    }

    // Validate string options
    const stringOptions = ['maxRequestSize', 'logLevel', 'logFilePath', 'blockMessage'];

    for (const option of stringOptions) {
      if (options[option] !== undefined && typeof options[option] !== 'string') {
        throw new Error(`Invalid ${option}: must be a string`);
      }
    }

    // Validate log level
    if (options.logLevel && !['debug', 'info', 'warn', 'error'].includes(options.logLevel)) {
      throw new Error('Invalid logLevel: must be one of debug, info, warn, error');
    }

    // Validate boolean options
    const booleanOptions = [
      'logToFile', 'enableCaptcha', 'enableJSChallenge',
      'enableHeuristicAnalysis', 'enableBehavioralAnalysis'
    ];

    for (const option of booleanOptions) {
      if (options[option] !== undefined && typeof options[option] !== 'boolean') {
        throw new Error(`Invalid ${option}: must be a boolean`);
      }
    }

    // Validate Redis configuration
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

    // Validate size format
    if (options.maxRequestSize) {
      const sizeRegex = /^(\d+)([a-z]+)$/i;
      if (!sizeRegex.test(options.maxRequestSize)) {
        throw new Error('Invalid maxRequestSize: must be in format like "10mb", "5kb", etc.');
      }
    }

    // Validate country codes
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

  // Initialize Redis with graceful degradation
  async initializeRedis() {
    try {
      this.redisClient = new redis(this.options.redis);

      // Set up error handling
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

  // Initialize logging system
  async initializeLogging() {
    if (this.options.logToFile) {
      try {
        // Create logs directory if it doesn't exist
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

  // Main middleware function
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
      
      // Check geographic restrictions
      const geoCheck = this.checkGeographicRestrictions(clientIP);
      if (!geoCheck.allowed) {
        this.log('warn', `Geographic restriction for ${clientIP}: ${geoCheck.reason}`, { 
          requestId, 
          clientIP, 
          country: geoCheck.country 
        });
        return this.sendBlockResponse(res, geoCheck.reason);
      }
      
      // Check user agent
      const userAgentCheck = this.checkUserAgent(userAgent);
      if (!userAgentCheck.allowed) {
        this.log('warn', `Blocked user agent from ${clientIP}: ${userAgent}`, { 
          requestId, 
          clientIP, 
          userAgent 
        });
        return this.sendBlockResponse(res, userAgentCheck.reason);
      }
      
      // Update connection count
      const connectionCheck = await this.updateConnectionCount(clientIP);
      if (!connectionCheck.allowed) {
        this.log('warn', `Too many connections from ${clientIP}`, { 
          requestId, 
          clientIP, 
          connections: connectionCheck.count 
        });
        return this.sendBlockResponse(res, 'TOO_MANY_CONNECTIONS');
      }
      
      // Update request counts
      const rateCheck = await this.updateRequestCounts(clientIP, timestamp);
      if (!rateCheck.allowed) {
        this.log('warn', `Rate limit exceeded for ${clientIP}`, { 
          requestId, 
          clientIP, 
          window: rateCheck.window 
        });
        return this.sendBlockResponse(res, 'RATE_LIMIT_EXCEEDED');
      }
      
      // Advanced detection
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
      
      // Behavioral analysis
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
      
      // If we get here, the request is allowed
      this.log('debug', `Allowed request from ${clientIP}`, { requestId, clientIP, method, url });
      
      // Add security headers
      this.addSecurityHeaders(res);
      
      // Continue to next middleware
      next();
    } catch (error) {
      this.log('error', `Error processing request from ${clientIP}: ${error.message}`, { 
        requestId, 
        clientIP, 
        error: error.stack 
      });
      
      // In case of error, we'll still allow the request to proceed
      // but log the error for investigation
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
        // Update in-memory cache
        this.blockedIPs.set(ip, blockInfo);
        return true;
      } else {
        // Block expired, remove it
        await this.safeRedisOperation(() => this.redisClient.del(`blocked:${ip}`));
      }
    }

    return false;
  }

  // Validate request structure
  validateRequest(req) {
    // Check URI length
    if (req.url.length > this.options.maxURILength) {
      return { 
        valid: false, 
        reason: 'URI_TOO_LONG' 
      };
    }
    
    // Check request size (approximate)
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
    
    // Check for suspicious headers
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

  // Parse size string to bytes
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

  // Check geographic restrictions
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
      
      // Update geo stats
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

  // Check user agent
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
    
    // Update user agent stats
    if (!this.userAgentStats.has(userAgent)) {
      this.userAgentStats.set(userAgent, { requests: 0, blocked: 0 });
    }
    const stats = this.userAgentStats.get(userAgent);
    stats.requests++;
    
    return { allowed: true };
  }

  // Update connection count
  async updateConnectionCount(ip) {
    // Update in-memory connection count
    let count = this.connectionCounts.get(ip) || 0;
    count++;
    this.connectionCounts.set(ip, count);

    // Update Redis connection count
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

    // Increment counters in Redis with fallback
    const [minuteCount, hourCount, dayCount] = await this.safeRedisOperation(
      async () => {
        const [min, hour, day] = await Promise.all([
          this.redisClient.incr(minuteKey),
          this.redisClient.incr(hourKey),
          this.redisClient.incr(dayKey)
        ]);

        // Set expiration times
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
    
    // Check for missing headers (bots often don't send all headers)
    const requiredHeaders = ['accept', 'accept-encoding', 'accept-language'];
    let missingHeaders = 0;
    
    if (!acceptHeader) missingHeaders++;
    if (!acceptEncoding) missingHeaders++;
    if (!acceptLanguage) missingHeaders++;
    
    if (missingHeaders >= 2) {
      this.incrementSuspiciousActivity(ip, 'MISSING_HEADERS');
      return { allowed: false, reason: 'MISSING_REQUIRED_HEADERS' };
    }
    
    // Check for suspicious patterns in URL
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

  // Perform behavioral analysis
  async performBehavioralAnalysis(ip, req) {
    // This is a simplified version - in a real implementation,
    // this would be much more complex and involve machine learning

    const now = Date.now();
    const key = `behavior:${ip}`;

    // Get previous request timestamps with fallback
    const timestamps = await this.safeRedisOperation(
      () => this.redisClient.lrange(key, 0, 99),
      () => []
    );
    const timestampsMs = timestamps.map(ts => parseInt(ts));

    // Add current timestamp
    await this.safeRedisOperation(
      async () => {
        await this.redisClient.lpush(key, now);
        await this.redisClient.ltrim(key, 0, 99);
        await this.redisClient.expire(key, 3600);
      },
      () => {} // No fallback needed for write operations
    );

    // Check for burst activity
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

  // Increment suspicious activity counter
  incrementSuspiciousActivity(ip, reason) {
    if (!this.suspiciousActivities.has(ip)) {
      this.suspiciousActivities.set(ip, new Map());
    }
    
    const ipActivities = this.suspiciousActivities.get(ip);
    const count = ipActivities.get(reason) || 0;
    ipActivities.set(reason, count + 1);
    
    // If too many suspicious activities, block IP
    const totalCount = Array.from(ipActivities.values()).reduce((sum, val) => sum + val, 0);
    if (totalCount > this.options.maxFailedAttempts) {
      this.blockIP(ip, 'TOO_MANY_SUSPICIOUS_ACTIVITIES');
    }
  }

  // Block an IP address
  async blockIP(ip, reason) {
    const expires = Date.now() + this.options.blockDuration;
    const blockInfo = {
      ip,
      reason,
      timestamp: Date.now(),
      expires
    };

    // Store in memory
    this.blockedIPs.set(ip, blockInfo);

    // Store in Redis with fallback
    await this.safeRedisOperation(
      () => this.redisClient.setex(
        `blocked:${ip}`,
        Math.ceil(this.options.blockDuration / 1000),
        JSON.stringify(blockInfo)
      ),
      () => {} // No fallback needed for write operations
    );

    // Update geo stats if available
    try {
      const geo = geoip.lookup(ip);
      if (geo && this.geoStats.has(geo.country)) {
        const stats = this.geoStats.get(geo.country);
        stats.blocked++;
      }
    } catch (error) {
      // Ignore geo lookup errors
    }

    this.log('info', `Blocked IP ${ip} for reason: ${reason}`, { ip, reason });
  }

  // Send block response
  sendBlockResponse(res, reason) {
    res.status(this.options.blockResponseCode).json({
      error: this.options.blockMessage,
      reason: reason,
      timestamp: new Date().toISOString()
    });
  }

  // Add security headers
  addSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
  }

  // Log messages
  log(level, message, data = {}) {
    if (this.shouldLog(level)) {
      const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        data
      };

      // Console output
      console.log(`[${level.toUpperCase()}] ${message}`, data);

      // File logging
      if (this.options.logToFile) {
        this.writeToFile(logEntry);
      }
    }
  }

  // Check if message should be logged based on log level
  shouldLog(level) {
    const levels = ['debug', 'info', 'warn', 'error'];
    const currentLevelIndex = levels.indexOf(this.options.logLevel);
    const messageLevelIndex = levels.indexOf(level);

    return messageLevelIndex >= currentLevelIndex;
  }

  // Write log entry to file
  async writeToFile(logEntry) {
    try {
      const logLine = JSON.stringify(logEntry) + '\n';
      await fs.appendFile(this.options.logFilePath, logLine);
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }
  }

  // Start cleanup interval
  startCleanupInterval() {
    setInterval(() => {
      const now = Date.now();

      // Clean up expired blocked IPs
      for (const [ip, blockInfo] of this.blockedIPs.entries()) {
        if (now > blockInfo.expires) {
          this.blockedIPs.delete(ip);
        }
      }

      // Clean up connection counts
      for (const [ip, count] of this.connectionCounts.entries()) {
        if (count <= 0) {
          this.connectionCounts.delete(ip);
        }
      }

      // Clean up suspicious activities
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

    // Also include in-memory blocked IPs
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

// Create middleware function
const createDDoSProtection = (options) => {
  const protection = new DDoSProtection(options);
  
  // Return middleware function
  return async (req, res, next) => {
    await protection.middleware(req, res, next);
  };
};

// Export both the class and the middleware creator
module.exports = {
  DDoSProtection,
  createDDoSProtection
};
