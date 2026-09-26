/**
 * BruteForceDetector - Advanced Sliding-Window Login Anomaly & Attack Engine
 */

class BruteForceDetector {
  constructor(config = {}) {
    this.config = {
      windowMs: config.windowMs || 30000,          // 30 second sliding window
      maxIpFailures: config.maxIpFailures || 5,      // Max failures per IP before block
      maxUserFailures: config.maxUserFailures || 8,  // Max failures per targeted user
      stuffingUserCount: config.stuffingUserCount || 3, // Unique users targeted by 1 IP
      lockoutMs: config.lockoutMs || 60000,         // 60 second IP lockout
      ...config
    };

    // Data structures for sliding window telemetry
    this.ipAttempts = new Map();     // ip -> array of { timestamp, username, success }
    this.userAttempts = new Map();   // username -> array of { timestamp, ip, success }
    
    // Security Lists & Block States
    this.blockedIps = new Map();     // ip -> { unblockTime, reason, blockTime }
    this.blacklistedIps = new Set(['192.168.1.666', '10.0.0.99']); // Permanently blocked IPs
    this.whitelistedIps = new Set(['127.0.0.1', '192.168.1.1']);   // Always allowed IPs

    // System Telemetry Metrics
    this.totalAttempts = 0;
    this.successfulLogins = 0;
    this.failedLogins = 0;
    this.blockedAttempts = 0;
    this.logs = [];                  // Array of log events (capped at 500)
    this.maxLogHistory = 500;
  }

  /**
   * Helper to clean up outdated timestamps outside the sliding window
   */
  _pruneWindow(records, now) {
    const cutoff = now - this.config.windowMs;
    return records.filter(r => r.timestamp > cutoff);
  }

  /**
   * Check if an IP address is blocked or blacklisted
   */
  isBlocked(ip) {
    if (this.whitelistedIps.has(ip)) return false;
    if (this.blacklistedIps.has(ip)) return { isBlocked: true, reason: 'PERMANENT_BLACKLIST', unblockTime: null };

    const blockInfo = this.blockedIps.get(ip);
    if (!blockInfo) return false;

    if (Date.now() > blockInfo.unblockTime) {
      // Lockout expired
      this.blockedIps.delete(ip);
      return false;
    }

    return { isBlocked: true, ...blockInfo };
  }

  /**
   * Manually or programmatically block an IP
   */
  blockIp(ip, durationMs = this.config.lockoutMs, reason = 'MANUAL_BLOCK') {
    if (this.whitelistedIps.has(ip)) return false;
    const now = Date.now();
    const blockInfo = {
      ip,
      reason,
      blockTime: now,
      unblockTime: now + durationMs
    };
    this.blockedIps.set(ip, blockInfo);
    return blockInfo;
  }

  /**
   * Unblock an IP address
   */
  unblockIp(ip) {
    this.blacklistedIps.delete(ip);
    return this.blockedIps.delete(ip);
  }

  /**
   * Add IP to permanent Blacklist
   */
  blacklistIp(ip) {
    this.whitelistedIps.delete(ip);
    this.blacklistedIps.add(ip);
  }

  /**
   * Add IP to Whitelist
   */
  whitelistIp(ip) {
    this.blacklistedIps.delete(ip);
    this.blockedIps.delete(ip);
    this.whitelistedIps.add(ip);
  }

  /**
   * Process an incoming login attempt and detect attack vectors
   */
  processLogin({ ip, username, success, userAgent = 'Unknown', location = 'Unknown' }) {
    const now = Date.now();
    this.totalAttempts++;

    // 1. Check if IP is currently blocked
    const blockStatus = this.isBlocked(ip);
    if (blockStatus) {
      this.blockedAttempts++;
      const blockedEvent = {
        id: `evt_${now}_${Math.random().toString(36).substr(2, 5)}`,
        timestamp: now,
        ip,
        username,
        status: 'BLOCKED',
        threatType: blockStatus.reason || 'IP_LOCKOUT',
        riskScore: 100,
        mitigation: 'REQUEST_REJECTED_403',
        userAgent,
        location
      };
      this._addLog(blockedEvent);
      return blockedEvent;
    }

    // Update global attempt counts
    if (success) {
      this.successfulLogins++;
    } else {
      this.failedLogins++;
    }

    // 2. Update Sliding Window Data Structures
    let ipHistory = this.ipAttempts.get(ip) || [];
    ipHistory = this._pruneWindow(ipHistory, now);
    ipHistory.push({ timestamp: now, username, success });
    this.ipAttempts.set(ip, ipHistory);

    let userHistory = this.userAttempts.get(username) || [];
    userHistory = this._pruneWindow(userHistory, now);
    userHistory.push({ timestamp: now, ip, success });
    this.userAttempts.set(username, userHistory);

    // If login succeeded and not whitelisted, we record it cleanly
    if (success) {
      const successEvent = {
        id: `evt_${now}_${Math.random().toString(36).substr(2, 5)}`,
        timestamp: now,
        ip,
        username,
        status: 'SUCCESS',
        threatType: 'NORMAL_TRAFFIC',
        riskScore: 0,
        mitigation: 'AUTHENTICATED',
        userAgent,
        location
      };
      this._addLog(successEvent);
      return successEvent;
    }

    // 3. Analyze Failed Login Threat Vectors
    const ipFailures = ipHistory.filter(r => !r.success);
    const userFailures = userHistory.filter(r => !r.success);
    const targetedUsersByIp = new Set(ipFailures.map(r => r.username));
    const attackingIpsByUser = new Set(userFailures.map(r => r.ip));

    let threatType = 'FAILED_LOGIN';
    let riskScore = 15;
    let mitigation = 'LOGGED';
    let autoBlocked = false;

    // Detection Rule A: Credential Stuffing (Single IP targeting multiple usernames)
    if (targetedUsersByIp.size >= this.config.stuffingUserCount) {
      threatType = 'CREDENTIAL_STUFFING';
      riskScore = 90;
      autoBlocked = true;
      mitigation = 'IP_AUTO_LOCKED';
      this.blockIp(ip, this.config.lockoutMs, 'CREDENTIAL_STUFFING_DETECTED');
    }
    // Detection Rule B: Single-IP Brute Force (High failure rate on single account or IP)
    else if (ipFailures.length >= this.config.maxIpFailures) {
      threatType = 'BRUTE_FORCE_ATTACK';
      riskScore = 95;
      autoBlocked = true;
      mitigation = 'IP_AUTO_LOCKED';
      this.blockIp(ip, this.config.lockoutMs, 'BRUTE_FORCE_THRESHOLD_EXCEEDED');
    }
    // Detection Rule C: Distributed Botnet / Spray Attack (Multiple IPs targeting one username)
    else if (userFailures.length >= this.config.maxUserFailures && attackingIpsByUser.size >= 2) {
      threatType = 'DISTRIBUTED_ATTACK';
      riskScore = 85;
      mitigation = 'ACCOUNT_RATE_LIMITED';
    }
    // Detection Rule D: Moderate Suspicious Activity
    else if (ipFailures.length >= 3) {
      threatType = 'SUSPICIOUS_VELOCITY';
      riskScore = 55;
      mitigation = 'CAPTCHA_TRIGGERED';
    }

    const event = {
      id: `evt_${now}_${Math.random().toString(36).substr(2, 5)}`,
      timestamp: now,
      ip,
      username,
      status: autoBlocked ? 'BLOCKED' : 'FAILED',
      threatType,
      riskScore,
      mitigation,
      ipFailureCount: ipFailures.length,
      userFailureCount: userFailures.length,
      userAgent,
      location
    };

    this._addLog(event);
    return event;
  }

  /**
   * Internal logger helper
   */
  _addLog(event) {
    this.logs.unshift(event);
    if (this.logs.length > this.maxLogHistory) {
      this.logs.pop();
    }
  }

  /**
   * Calculate System Threat Level
   */
  getSystemThreatLevel() {
    const recentLogs = this.logs.slice(0, 30);
    if (recentLogs.length === 0) return 'LOW';
    
    const highRiskCount = recentLogs.filter(l => l.riskScore >= 80).length;
    const moderateRiskCount = recentLogs.filter(l => l.riskScore >= 40).length;

    if (highRiskCount >= 3) return 'CRITICAL';
    if (highRiskCount >= 1 || moderateRiskCount >= 5) return 'ELEVATED';
    return 'LOW';
  }

  /**
   * Get Aggregated Dashboard Analytics
   */
  getStats() {
    const now = Date.now();
    
    // Top Attacking IPs
    const ipCounts = {};
    const userCounts = {};
    const threatCounts = {};

    this.logs.forEach(l => {
      if (l.status === 'FAILED' || l.status === 'BLOCKED') {
        ipCounts[l.ip] = (ipCounts[l.ip] || 0) + 1;
        userCounts[l.username] = (userCounts[l.username] || 0) + 1;
      }
      threatCounts[l.threatType] = (threatCounts[l.threatType] || 0) + 1;
    });

    const topAttackingIps = Object.entries(ipCounts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const topTargetedUsers = Object.entries(userCounts)
      .map(([username, count]) => ({ username, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Active Blocks array
    const activeBlocks = [];
    for (const [ip, info] of this.blockedIps.entries()) {
      if (now <= info.unblockTime) {
        activeBlocks.push({
          ip,
          reason: info.reason,
          blockTime: info.blockTime,
          unblockTime: info.unblockTime,
          remainingSec: Math.ceil((info.unblockTime - now) / 1000)
        });
      }
    }

    return {
      totalAttempts: this.totalAttempts,
      successfulLogins: this.successfulLogins,
      failedLogins: this.failedLogins,
      blockedAttempts: this.blockedAttempts,
      threatLevel: this.getSystemThreatLevel(),
      activeBlockCount: activeBlocks.length + this.blacklistedIps.size,
      activeBlocks,
      blacklistedIps: Array.from(this.blacklistedIps),
      whitelistedIps: Array.from(this.whitelistedIps),
      topAttackingIps,
      topTargetedUsers,
      threatCounts,
      config: this.config
    };
  }

  /**
   * Dynamic Configuration Update
   */
  updateConfig(newConfig) {
    this.config = {
      ...this.config,
      ...newConfig
    };
    return this.config;
  }

  /**
   * Reset logs and counters
   */
  clearLogs() {
    this.logs = [];
    this.ipAttempts.clear();
    this.userAttempts.clear();
    this.totalAttempts = 0;
    this.successfulLogins = 0;
    this.failedLogins = 0;
    this.blockedAttempts = 0;
  }
}

module.exports = BruteForceDetector;
