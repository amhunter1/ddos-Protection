const { DDoSProtection, createDDoSProtection } = require('./src/middleware/ddosProtection');

module.exports = {
  DDoSProtection,
  createDDoSProtection,
 
  createExpressMiddleware: createDDoSProtection,
  createKoaMiddleware: (options) => {
    const protection = new DDoSProtection(options);
    return async (ctx, next) => {
      // Convert Express-style req/res to Koa-style ctx
      const req = {
        ip: ctx.ip,
        method: ctx.method,
        url: ctx.url,
        headers: ctx.headers,
        get: (header) => ctx.get(header),
        query: ctx.query,
        body: ctx.request.body
      };

      const res = {
        status: (code) => { ctx.status = code; return res; },
        json: (data) => { ctx.body = data; },
        setHeader: (name, value) => ctx.set(name, value)
      };

      let nextCalled = false;
      const nextFn = () => { nextCalled = true; };

      await protection.middleware(req, res, nextFn);

      if (nextCalled) {
        await next();
      }
    };
  },

  createFastifyMiddleware: (options) => {
    const protection = new DDoSProtection(options);
    return async (request, reply) => {
      const req = {
        ip: request.ip,
        method: request.method,
        url: request.url,
        headers: request.headers,
        get: (header) => request.headers[header],
        query: request.query,
        body: request.body
      };

      const res = {
        status: (code) => { reply.code(code); return res; },
        json: (data) => reply.send(data),
        setHeader: (name, value) => reply.header(name, value)
      };

      let nextCalled = false;
      const nextFn = () => { nextCalled = true; };

      await protection.middleware(req, res, nextFn);

      if (!nextCalled) {
        return reply;
      }
    };
  }
};

if (require.main === module) {
  console.log(`
DDoS Protection System for Node.js

Usage:
  const { createDDoSProtection } = require('ddos-protection-system');

  //Express
  app.use(createDDoSProtection({
    maxRequestsPerMinute: 100,
    // ... other options
  }));

  //Koa
  const { createKoaMiddleware } = require('ddos-protection-system');
  app.use(createKoaMiddleware(options));

  //Fastify
  const { createFastifyMiddleware } = require('ddos-protection-system');
  fastify.register(require('fastify-express')).after(() => {
    fastify.use(createFastifyMiddleware(options));
  });

Available options:
  - Rate limiting: maxRequestsPerMinute, maxRequestsPerHour, maxRequestsPerDay
  - Burst protection: burstThreshold, burstWindow
  - IP blocking: blockDuration, maxFailedAttempts
  - Geographic filtering: blockedCountries, allowedCountries
  - User agent filtering: blockedUserAgents, suspiciousUserAgents
  - Request limits: maxRequestSize, maxURILength, maxConnectionsPerIP
  - Redis config: redis.host, redis.port, redis.password
  - Logging: logLevel, logToFile, logFilePath
  - Whitelisting: whitelistedIPs, whitelistedUserAgents
  - Advanced features: enableHeuristicAnalysis, enableBehavioralAnalysis
  - Response config: blockResponseCode, blockMessage

For more information, see the README.md file.
  `);
}
