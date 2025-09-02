#!/usr/bin/env node

const { DDoSProtection } = require('./src/middleware/ddosProtection');
const fs = require('fs').promises;
const path = require('path');

class DDoSCLI {
  constructor() {
    this.protection = null;
  }

  async initialize(options = {}) {
    this.protection = new DDoSProtection({
      logLevel: 'info',
      ...options
    });

    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  async showStats() {
    if (!this.protection) {
      console.log('❌ DDoS protection not initialized');
      return;
    }

    try {
      const stats = await this.protection.getStats();
      console.log('\n📊 DDoS Protection Statistics:');
      console.log('=' .repeat(40));
      console.log(`Blocked IPs: ${stats.blockedIPs}`);
      console.log(`Active Connections: ${stats.activeConnections}`);
      console.log(`Total Requests: ${stats.totalRequests}`);
      console.log(`In-Memory Blocked: ${stats.inMemoryBlocked}`);
      console.log(`In-Memory Connections: ${stats.inMemoryConnections}`);
      console.log(`Suspicious Activities: ${stats.suspiciousActivities}`);
      console.log(`User Agent Stats: ${stats.userAgentStats}`);
      console.log(`Geo Stats: ${stats.geoStats}`);
      console.log(`Redis Available: ${stats.redisAvailable ? '✅' : '❌'}`);
    } catch (error) {
      console.log('❌ Failed to get statistics:', error.message);
    }
  }

  async showBlockedIPs() {
    if (!this.protection) {
      console.log('❌ DDoS protection not initialized');
      return;
    }

    try {
      const blockedIPs = await this.protection.getBlockedIPs();
      console.log('\n🚫 Blocked IPs:');
      console.log('=' .repeat(40));

      if (blockedIPs.length === 0) {
        console.log('No IPs are currently blocked');
        return;
      }

      blockedIPs.forEach((block, index) => {
        const expires = new Date(block.expires).toLocaleString();
        console.log(`${index + 1}. IP: ${block.ip}`);
        console.log(`   Reason: ${block.reason}`);
        console.log(`   Blocked: ${new Date(block.timestamp).toLocaleString()}`);
        console.log(`   Expires: ${expires}`);
        console.log('');
      });
    } catch (error) {
      console.log('❌ Failed to get blocked IPs:', error.message);
    }
  }

  async unblockIP(ip) {
    if (!this.protection) {
      console.log('❌ DDoS protection not initialized');
      return;
    }

    if (!ip) {
      console.log('❌ Please provide an IP address to unblock');
      return;
    }

    try {
      await this.protection.unblockIP(ip);
      console.log(`✅ Successfully unblocked IP: ${ip}`);
    } catch (error) {
      console.log(`❌ Failed to unblock IP ${ip}:`, error.message);
    }
  }

  async showConfig() {
    try {
      const whitelistPath = path.join(__dirname, 'src/config/whitelist.json');
      const blocklistPath = path.join(__dirname, 'src/config/blocklist.json');

      console.log('\n⚙️  Configuration:');
      console.log('=' .repeat(40));

      try {
        const whitelistData = await fs.readFile(whitelistPath, 'utf8');
        const whitelist = JSON.parse(whitelistData);
        console.log('\n📋 Whitelist:');
        console.log(`   IPs: ${whitelist.ips?.join(', ') || 'None'}`);
        console.log(`   User Agents: ${whitelist.userAgents?.join(', ') || 'None'}`);
      } catch (error) {
        console.log('\n📋 Whitelist: Not found or invalid');
      }

      try {
        const blocklistData = await fs.readFile(blocklistPath, 'utf8');
        const blocklist = JSON.parse(blocklistData);
        console.log('\n🚫 Blocklist:');
        console.log(`   Countries: ${blocklist.countries?.join(', ') || 'None'}`);
        console.log(`   User Agents: ${blocklist.userAgents?.join(', ') || 'None'}`);
        console.log(`   IP Ranges: ${blocklist.ipRanges?.join(', ') || 'None'}`);
      } catch (error) {
        console.log('\n🚫 Blocklist: Not found or invalid');
      }
    } catch (error) {
      console.log('❌ Failed to load configuration:', error.message);
    }
  }

  showHelp() {
    console.log('\n🛡️  DDoS Protection CLI Tool');
    console.log('=' .repeat(40));
    console.log('');
    console.log('Usage: node cli.js <command> [options]');
    console.log('');
    console.log('Commands:');
    console.log('  stats          Show DDoS protection statistics');
    console.log('  blocked        Show list of blocked IPs');
    console.log('  unblock <ip>   Unblock a specific IP address');
    console.log('  config         Show current configuration');
    console.log('  help           Show this help message');
    console.log('');
    console.log('Examples:');
    console.log('  node cli.js stats');
    console.log('  node cli.js blocked');
    console.log('  node cli.js unblock 192.168.1.100');
    console.log('  node cli.js config');
    console.log('');
  }

  async run() {
    const args = process.argv.slice(2);
    const command = args[0];
    await this.initialize();

    switch (command) {
      case 'stats':
        await this.showStats();
        break;

      case 'blocked':
        await this.showBlockedIPs();
        break;

      case 'unblock':
        const ip = args[1];
        await this.unblockIP(ip);
        break;

      case 'config':
        await this.showConfig();
        break;

      case 'help':
      default:
        this.showHelp();
        break;
    }

    // Clean
    if (this.protection) {
      await this.protection.close();
    }
  }
}

if (require.main === module) {
  const cli = new DDoSCLI();
  cli.run().catch(error => {
    console.error('CLI Error:', error.message);
    process.exit(1);
  });
}

module.exports = DDoSCLI;
