// Phishing Detector Background Script
// This service worker handles background tasks and communication

class PhishingBackground {
    constructor() {
        this.isProtectionEnabled = true;
        this.realTimeScanning = true;
        this.blockedSites = new Set();
        this.analysisCache = new Map();
        
        this.init();
    }

    init() {
        console.log('Phishing Detector Background: Initializing...');
        
        // Load settings
        this.loadSettings();
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Initialize context menu
        this.setupContextMenu();
        
        // Set up periodic cleanup
        this.setupPeriodicTasks();
    }

    async loadSettings() {
        const settings = await chrome.storage.sync.get({
            protectionEnabled: true,
            realTimeScanning: true,
            warningPopups: true,
            soundAlerts: false,
            threatsBlocked: 0,
            sitesScanned: 0
        });
        
        this.isProtectionEnabled = settings.protectionEnabled;
        this.realTimeScanning = settings.realTimeScanning;
        this.warningPopups = settings.warningPopups;
        this.soundAlerts = settings.soundAlerts;
        this.stats = {
            threatsBlocked: settings.threatsBlocked,
            sitesScanned: settings.sitesScanned
        };
    }

    setupEventListeners() {
        // Listen for tab updates
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete' && tab.url && this.realTimeScanning) {
                this.analyzeTab(tab);
            }
        });
        
        // Listen for navigation
        chrome.webNavigation.onBeforeNavigate.addListener((details) => {
            if (details.frameId === 0 && this.isProtectionEnabled) {
                this.checkNavigationSafety(details);
            }
        });
        
        // Listen for messages from content scripts and popup
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open for async responses
        });
        
        // Listen for extension installation
        chrome.runtime.onInstalled.addListener((details) => {
            if (details.reason === 'install') {
                this.onFirstInstall();
            }
        });
        
        // Listen for alarm events
        chrome.alarms.onAlarm.addListener((alarm) => {
            this.handleAlarm(alarm);
        });
    }

    setupContextMenu() {
        chrome.contextMenus.create({
            id: 'scan-page',
            title: 'Scan this page for phishing',
            contexts: ['page']
        });
        
        chrome.contextMenus.create({
            id: 'report-phishing',
            title: 'Report as phishing site',
            contexts: ['page']
        });
        
        chrome.contextMenus.onClicked.addListener((info, tab) => {
            this.handleContextMenuClick(info, tab);
        });
    }

    setupPeriodicTasks() {
        // Clean up old cache entries every hour
        chrome.alarms.create('cleanup-cache', { periodInMinutes: 60 });
        
        // Update threat database every 6 hours
        chrome.alarms.create('update-threats', { periodInMinutes: 360 });
    }

    async analyzeTab(tab) {
        if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            return;
        }
        
        console.log('Phishing Detector: Analyzing tab:', tab.url);
        
        try {
            // Check cache first
            const cacheKey = this.getCacheKey(tab.url);
            if (this.analysisCache.has(cacheKey)) {
                const cachedResult = this.analysisCache.get(cacheKey);
                if (Date.now() - cachedResult.timestamp < 300000) { // 5 minutes
                    return cachedResult;
                }
            }
            
            // Perform analysis
            const analysis = await this.performURLAnalysis(tab.url);
            
            // Cache result
            this.analysisCache.set(cacheKey, {
                ...analysis,
                timestamp: Date.now()
            });
            
            // Update statistics
            this.stats.sitesScanned++;
            if (analysis.riskLevel === 'danger') {
                this.stats.threatsBlocked++;
            }
            
            await this.saveStats();
            
            // Take action if dangerous
            if (analysis.riskLevel === 'danger' && this.isProtectionEnabled) {
                await this.handleDangerousSite(tab, analysis);
            }
            
            // Update badge
            this.updateBadge(tab.id, analysis);
            
            return analysis;
            
        } catch (error) {
            console.error('Phishing Detector: Error analyzing tab:', error);
        }
    }

    async performURLAnalysis(url) {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        
        const analysis = {
            url: url,
            domain: domain,
            timestamp: Date.now(),
            riskLevel: 'safe',
            score: 100,
            threats: [],
            checks: {
                blacklist: await this.checkBlacklist(domain),
                reputation: await this.checkDomainReputation(domain),
                structure: this.checkURLStructure(url, domain),
                ssl: this.checkSSLStatus(urlObj),
                phishingPatterns: this.checkPhishingPatterns(url, domain)
            }
        };
        
        // Calculate overall score
        const scores = Object.values(analysis.checks).map(check => check.score);
        analysis.score = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
        
        // Collect all threats
        Object.values(analysis.checks).forEach(check => {
            if (check.threats) {
                analysis.threats.push(...check.threats);
            }
        });
        
        // Determine risk level
        if (analysis.score < 40) {
            analysis.riskLevel = 'danger';
        } else if (analysis.score < 70) {
            analysis.riskLevel = 'warning';
        } else {
            analysis.riskLevel = 'safe';
        }
        
        return analysis;
    }

    async checkBlacklist(domain) {
        // In a real implementation, this would check against known phishing databases
        const knownPhishingDomains = [
            'phishing-example.com',
            'fake-bank.net',
            'suspicious-site.org'
        ];
        
        const isBlacklisted = knownPhishingDomains.includes(domain);
        
        return {
            score: isBlacklisted ? 0 : 100,
            threats: isBlacklisted ? ['Domain is blacklisted'] : []
        };
    }

    async checkDomainReputation(domain) {
        const threats = [];
        let score = 100;
        
        // Check for suspicious TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click'];
        if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
            threats.push('Suspicious top-level domain');
            score -= 30;
        }
        
        // Check for typosquatting of popular domains
        const popularDomains = [
            'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'instagram.com'
        ];
        
        for (const popular of popularDomains) {
            if (this.isTyposquatting(domain, popular)) {
                threats.push(`Possible typosquatting of ${popular}`);
                score -= 50;
                break;
            }
        }
        
        // Check for suspicious keywords
        const suspiciousKeywords = ['secure', 'verify', 'update', 'login', 'account'];
        for (const keyword of suspiciousKeywords) {
            if (domain.includes(keyword) && !popularDomains.includes(domain)) {
                threats.push(`Suspicious keyword in domain: ${keyword}`);
                score -= 20;
            }
        }
        
        return {
            score: Math.max(0, score),
            threats: threats
        };
    }

    checkURLStructure(url, domain) {
        const threats = [];
        let score = 100;
        
        // Check for excessive subdomains
        const subdomains = domain.split('.').length - 2;
        if (subdomains > 3) {
            threats.push('Excessive subdomains');
            score -= 25;
        }
        
        // Check for suspicious URL patterns
        const suspiciousPatterns = [
            /login.*verify/i,
            /account.*suspend/i,
            /security.*alert/i,
            /urgent.*action/i
        ];
        
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(url)) {
                threats.push('Suspicious URL pattern');
                score -= 30;
                break;
            }
        }
        
        // Check for IP addresses
        const ipPattern = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
        if (ipPattern.test(url)) {
            threats.push('IP address used instead of domain');
            score -= 40;
        }
        
        return {
            score: Math.max(0, score),
            threats: threats
        };
    }

    checkSSLStatus(urlObj) {
        const threats = [];
        let score = 100;
        
        if (urlObj.protocol !== 'https:') {
            threats.push('No SSL encryption');
            score -= 50;
        }
        
        return {
            score: Math.max(0, score),
            threats: threats
        };
    }

    checkPhishingPatterns(url, domain) {
        const threats = [];
        let score = 100;
        
        // Check for URL shorteners
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
        if (shorteners.some(shortener => domain.includes(shortener))) {
            threats.push('URL shortener detected');
            score -= 30;
        }
        
        // Check for redirect parameters
        if (url.includes('redirect=') || url.includes('url=') || url.includes('goto=')) {
            threats.push('Redirect parameters detected');
            score -= 25;
        }
        
        return {
            score: Math.max(0, score),
            threats: threats
        };
    }

    isTyposquatting(domain, legitimate) {
        if (domain === legitimate) return false;
        
        // Simple Levenshtein distance check
        const distance = this.levenshteinDistance(domain, legitimate);
        return distance <= 2 && domain.length >= legitimate.length - 2;
    }

    levenshteinDistance(str1, str2) {
        const matrix = [];
        
        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }
        
        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }
        
        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }
        
        return matrix[str2.length][str1.length];
    }

    async handleDangerousSite(tab, analysis) {
        console.log('Phishing Detector: Dangerous site detected:', tab.url);
        
        // Add to blocked sites
        this.blockedSites.add(analysis.domain);
        
        // Show notification
        if (this.warningPopups) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2VmNDQ0NCI+PHBhdGggZD0iTTEzLDE0SDExVjEwSDEzTTEzLDE4SDExVjE2SDEzTTEsMjFIMjNMMTIsMkwxLDIxWiIvPjwvc3ZnPg==',
                title: 'Phishing Threat Detected!',
                message: `Dangerous website blocked: ${analysis.domain}`
            });
        }
        
        // Inject warning into page
        try {
            await chrome.tabs.sendMessage(tab.id, {
                action: 'showWarning',
                analysis: analysis
            });
        } catch (error) {
            console.log('Could not inject warning into page:', error);
        }
    }

    updateBadge(tabId, analysis) {
        let badgeText = '';
        let badgeColor = '#10b981'; // Green for safe
        
        if (analysis.riskLevel === 'danger') {
            badgeText = '!';
            badgeColor = '#ef4444'; // Red for danger
        } else if (analysis.riskLevel === 'warning') {
            badgeText = '?';
            badgeColor = '#f59e0b'; // Yellow for warning
        }
        
        chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });
    }

    async handleMessage(message, sender, sendResponse) {
        switch (message.action) {
            case 'toggleProtection':
                this.isProtectionEnabled = message.enabled;
                await this.saveSettings();
                sendResponse({ success: true });
                break;
                
            case 'toggleRealTimeScanning':
                this.realTimeScanning = message.enabled;
                await this.saveSettings();
                sendResponse({ success: true });
                break;
                
            case 'siteAnalyzed':
                // Handle analysis from popup
                console.log('Site analyzed:', message.analysis);
                sendResponse({ success: true });
                break;
                
            case 'reportSite':
                await this.reportPhishingSite(message.url);
                sendResponse({ success: true });
                break;
                
            case 'getStats':
                sendResponse(this.stats);
                break;
                
            default:
                sendResponse({ error: 'Unknown action' });
        }
    }

    async handleContextMenuClick(info, tab) {
        switch (info.menuItemId) {
            case 'scan-page':
                if (tab && tab.url) {
                    const analysis = await this.analyzeTab(tab);
                    chrome.notifications.create({
                        type: 'basic',
                        iconUrl: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iIzEwYjk4MSI+PHBhdGggZD0iTTIxLDdMOSwxOUwzLjUsMTMuNUw0LjkxLDEyLjA5TDksMTYuMTdMMTkuNTksNS41OUwyMSw3WiIvPjwvc3ZnPg==',
                        title: 'Scan Complete',
                        message: `Site safety score: ${analysis.score}/100 (${analysis.riskLevel})`
                    });
                }
                break;
                
            case 'report-phishing':
                if (tab && tab.url) {
                    await this.reportPhishingSite(tab.url);
                    chrome.notifications.create({
                        type: 'basic',
                        iconUrl: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iIzEwYjk4MSI+PHBhdGggZD0iTTIxLDdMOSwxOUwzLjUsMTMuNUw0LjkxLDEyLjA5TDksMTYuMTdMMTkuNTksNS41OUwyMSw3WiIvPjwvc3ZnPg==',
                        title: 'Report Submitted',
                        message: 'Thank you for reporting this suspicious site!'
                    });
                }
                break;
        }
    }

    async reportPhishingSite(url) {
        console.log('Reporting phishing site:', url);
        // In a real implementation, this would send the report to a security service
        
        // Add to local blacklist
        const urlObj = new URL(url);
        this.blockedSites.add(urlObj.hostname);
        
        // Save to storage
        const blockedArray = Array.from(this.blockedSites);
        await chrome.storage.local.set({ blockedSites: blockedArray });
    }

    handleAlarm(alarm) {
        switch (alarm.name) {
            case 'cleanup-cache':
                this.cleanupCache();
                break;
                
            case 'update-threats':
                this.updateThreatDatabase();
                break;
        }
    }

    cleanupCache() {
        const now = Date.now();
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        
        for (const [key, value] of this.analysisCache.entries()) {
            if (now - value.timestamp > maxAge) {
                this.analysisCache.delete(key);
            }
        }
        
        console.log('Phishing Detector: Cache cleaned up');
    }

    async updateThreatDatabase() {
        console.log('Phishing Detector: Updating threat database...');
        // In a real implementation, this would fetch updated threat data
    }

    onFirstInstall() {
        console.log('Phishing Detector: First installation detected');
        
        // Show welcome notification
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iIzEwYjk4MSI+PHBhdGggZD0iTTEyLDJBMTAsMTAgMCAwLDEgMjIsMTJBMTAsMTAgMCAwLDEgMTIsMjJBMTAsMTAgMCAwLDEgMiwxMkExMCwxMCAwIDAsMSAxMiwyTTExLDE2LjVMMTgsOS41TDE2LjU5LDguMDlMMTEsMTMuNjdMNy40MSwxMC4wOUw2LDExLjVMMTEsMTYuNVoiLz48L3N2Zz4=',
            title: 'Phishing Detector Installed!',
            message: 'Your browser is now protected against phishing attacks.'
        });
        
        // Set default settings
        chrome.storage.sync.set({
            protectionEnabled: true,
            realTimeScanning: true,
            warningPopups: true,
            soundAlerts: false,
            advancedMode: false,
            threatsBlocked: 0,
            sitesScanned: 0,
            avgScore: 100
        });
    }

    async saveSettings() {
        await chrome.storage.sync.set({
            protectionEnabled: this.isProtectionEnabled,
            realTimeScanning: this.realTimeScanning,
            warningPopups: this.warningPopups,
            soundAlerts: this.soundAlerts
        });
    }

    async saveStats() {
        await chrome.storage.sync.set({
            threatsBlocked: this.stats.threatsBlocked,
            sitesScanned: this.stats.sitesScanned
        });
    }

    getCacheKey(url) {
        const urlObj = new URL(url);
        return urlObj.hostname;
    }

    checkNavigationSafety(details) {
        // Quick check before navigation
        const url = details.url;
        if (this.blockedSites.has(new URL(url).hostname)) {
            // Block navigation to known dangerous sites
            chrome.tabs.update(details.tabId, { url: 'chrome://newtab/' });
        }
    }
}

// Initialize background script
const phishingBackground = new PhishingBackground();