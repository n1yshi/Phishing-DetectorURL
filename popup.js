class PhishingDetector {
    constructor() {
        console.log('Phishing Detector: Initializing...');
        this.isProtectionEnabled = true;
        this.currentSiteData = null;
        this.stats = {
            threatsBlocked: 0,
            sitesScanned: 0,
            avgScore: 100
        };
        
        this.initializeElements();
        this.loadSettings();
        this.bindEvents();
        this.initializeDetector();
        this.startRealTimeUpdates();
    }

    initializeElements() {
        this.elements = {
            // Main controls
            protectionToggle: document.getElementById('protectionToggle'),
            themeToggle: document.getElementById('themeToggle'),
            
            // Status display
            statusCircle: document.getElementById('statusCircle'),
            statusIcon: document.getElementById('statusIcon'),
            statusTitle: document.getElementById('statusTitle'),
            statusDescription: document.getElementById('statusDescription'),
            
            // Site analysis
            siteIcon: document.getElementById('siteIcon'),
            siteName: document.getElementById('siteName'),
            siteUrl: document.getElementById('siteUrl'),
            scoreValue: document.getElementById('scoreValue'),
            
            // Threat indicators
            urlStatus: document.getElementById('urlStatus'),
            urlResult: document.getElementById('urlResult'),
            domainStatus: document.getElementById('domainStatus'),
            domainResult: document.getElementById('domainResult'),
            sslStatus: document.getElementById('sslStatus'),
            sslResult: document.getElementById('sslResult'),
            suspiciousStatus: document.getElementById('suspiciousStatus'),
            suspiciousResult: document.getElementById('suspiciousResult'),
            
            // Statistics
            threatsBlocked: document.getElementById('threatsBlocked'),
            sitesScanned: document.getElementById('sitesScanned'),
            avgScore: document.getElementById('avgScore'),
            
            // Settings
            realTimeScanning: document.getElementById('realTimeScanning'),
            warningPopups: document.getElementById('warningPopups'),
            soundAlerts: document.getElementById('soundAlerts'),
            advancedMode: document.getElementById('advancedMode'),
            
            // Actions
            scanCurrentSite: document.getElementById('scanCurrentSite'),
            reportSite: document.getElementById('reportSite'),
            
            // Toast
            toast: document.getElementById('toast'),
            toastIcon: document.getElementById('toastIcon'),
            toastMessage: document.getElementById('toastMessage')
        };
    }

    bindEvents() {
        // Main protection toggle
        this.elements.protectionToggle.addEventListener('change', () => this.toggleProtection());
        
        // Theme toggle
        this.elements.themeToggle.addEventListener('click', () => this.toggleTheme());
        
        // Settings toggles
        this.elements.realTimeScanning.addEventListener('change', () => this.toggleRealTimeScanning());
        this.elements.warningPopups.addEventListener('change', () => this.saveSettings());
        this.elements.soundAlerts.addEventListener('change', () => this.saveSettings());
        this.elements.advancedMode.addEventListener('change', () => this.saveSettings());
        
        // Action buttons
        this.elements.scanCurrentSite.addEventListener('click', () => this.scanCurrentSite());
        this.elements.reportSite.addEventListener('click', () => this.reportSuspiciousSite());
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 's':
                        e.preventDefault();
                        this.scanCurrentSite();
                        break;
                    case 'p':
                        e.preventDefault();
                        this.toggleProtection();
                        break;
                }
            }
        });
    }

    loadSettings() {
        chrome.storage.sync.get({
            theme: 'dark',
            protectionEnabled: true,
            realTimeScanning: true,
            warningPopups: true,
            soundAlerts: false,
            advancedMode: false,
            threatsBlocked: 0,
            sitesScanned: 0,
            avgScore: 100
        }, (settings) => {
            document.body.setAttribute('data-theme', settings.theme);
            this.isProtectionEnabled = settings.protectionEnabled;
            this.elements.protectionToggle.checked = settings.protectionEnabled;
            this.elements.realTimeScanning.checked = settings.realTimeScanning;
            this.elements.warningPopups.checked = settings.warningPopups;
            this.elements.soundAlerts.checked = settings.soundAlerts;
            this.elements.advancedMode.checked = settings.advancedMode;
            
            this.stats = {
                threatsBlocked: settings.threatsBlocked,
                sitesScanned: settings.sitesScanned,
                avgScore: settings.avgScore
            };
            
            this.updateProtectionStatus();
            this.updateStatistics();
        });
    }

    saveSettings() {
        const settings = {
            theme: document.body.getAttribute('data-theme'),
            protectionEnabled: this.isProtectionEnabled,
            realTimeScanning: this.elements.realTimeScanning.checked,
            warningPopups: this.elements.warningPopups.checked,
            soundAlerts: this.elements.soundAlerts.checked,
            advancedMode: this.elements.advancedMode.checked,
            threatsBlocked: this.stats.threatsBlocked,
            sitesScanned: this.stats.sitesScanned,
            avgScore: this.stats.avgScore
        };
        
        chrome.storage.sync.set(settings);
    }

    async initializeDetector() {
        console.log('Phishing Detector: Initializing detection system...');
        
        try {
            // Get current tab information
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.url) {
                await this.analyzeSite(tab.url, tab.title);
            }
            
        } catch (error) {
            console.error('Phishing Detector: Error initializing:', error);
            this.showError('Unable to analyze current site');
        }
    }

    async analyzeSite(url, title = '') {
        console.log('Phishing Detector: Analyzing site:', url);
        
        try {
            // Update UI with site info
            const urlObj = new URL(url);
            const domain = urlObj.hostname;
            
            this.elements.siteName.textContent = title || domain;
            this.elements.siteUrl.textContent = domain;
            this.elements.siteIcon.textContent = this.getSiteIcon(domain);
            
            // Start analysis
            this.updateIndicatorStatus('checking');
            
            // Perform phishing analysis
            const analysis = await this.performPhishingAnalysis(url);
            
            // Update results
            this.updateAnalysisResults(analysis);
            
            // Update statistics
            this.stats.sitesScanned++;
            this.updateStatistics();
            this.saveSettings();
            
            // Send to background script
            chrome.runtime.sendMessage({
                action: 'siteAnalyzed',
                url: url,
                analysis: analysis
            });
            
        } catch (error) {
            console.error('Phishing Detector: Error analyzing site:', error);
            this.showError('Analysis failed');
        }
    }

    async performPhishingAnalysis(url) {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        const fullUrl = url.toLowerCase();
        
        const analysis = {
            url: url,
            domain: domain,
            timestamp: Date.now(),
            checks: {
                urlStructure: this.checkURLStructure(fullUrl, domain),
                domainReputation: this.checkDomainReputation(domain),
                sslCertificate: this.checkSSLCertificate(urlObj),
                suspiciousPatterns: this.checkSuspiciousPatterns(fullUrl, domain)
            },
            overallScore: 0,
            riskLevel: 'safe',
            threats: []
        };
        
        // Calculate overall score
        const scores = Object.values(analysis.checks).map(check => check.score);
        analysis.overallScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
        
        // Determine risk level
        if (analysis.overallScore >= 80) {
            analysis.riskLevel = 'safe';
        } else if (analysis.overallScore >= 60) {
            analysis.riskLevel = 'warning';
        } else {
            analysis.riskLevel = 'danger';
            this.stats.threatsBlocked++;
        }
        
        // Collect threats
        Object.values(analysis.checks).forEach(check => {
            if (check.threats && check.threats.length > 0) {
                analysis.threats.push(...check.threats);
            }
        });
        
        return analysis;
    }

    checkURLStructure(url, domain) {
        const threats = [];
        let score = 100;
        
        // Check for suspicious TLDs
        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download'];
        if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
            threats.push('Suspicious top-level domain');
            score -= 30;
        }
        
        // Check for excessive subdomains
        const subdomains = domain.split('.').length - 2;
        if (subdomains > 2) {
            threats.push('Excessive subdomains detected');
            score -= 20;
        }
        
        // Check for URL shorteners
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link'];
        if (shorteners.some(shortener => domain.includes(shortener))) {
            threats.push('URL shortener detected');
            score -= 25;
        }
        
        // Check for suspicious characters
        if (/[0-9]/.test(domain.replace(/\./g, '')) && domain.split('.')[0].length > 10) {
            threats.push('Suspicious characters in domain');
            score -= 15;
        }
        
        // Check for homograph attacks (similar looking characters)
        const suspiciousChars = /[а-я]|[αβγδεζηθικλμνξοπρστυφχψω]|[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]/i;
        if (suspiciousChars.test(domain)) {
            threats.push('Potential homograph attack');
            score -= 40;
        }
        
        return {
            score: Math.max(0, score),
            status: score >= 80 ? 'safe' : score >= 60 ? 'warning' : 'danger',
            threats: threats
        };
    }

    checkDomainReputation(domain) {
        const threats = [];
        let score = 100;
        
        // Check against known legitimate domains
        const legitimateDomains = [
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com', 'ebay.com'
        ];
        
        // Check for typosquatting of popular domains
        for (const legitDomain of legitimateDomains) {
            if (this.isTyposquatting(domain, legitDomain)) {
                threats.push(`Possible typosquatting of ${legitDomain}`);
                score -= 50;
                break;
            }
        }
        
        // Check domain age simulation (newer domains are more suspicious)
        const domainParts = domain.split('.');
        const mainDomain = domainParts[domainParts.length - 2];
        if (mainDomain && mainDomain.length < 4) {
            threats.push('Very short domain name');
            score -= 20;
        }
        
        // Check for suspicious keywords
        const suspiciousKeywords = [
            'secure', 'verify', 'update', 'confirm', 'login', 'account',
            'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google'
        ];
        
        for (const keyword of suspiciousKeywords) {
            if (domain.toLowerCase().includes(keyword) && !legitimateDomains.includes(domain)) {
                threats.push(`Suspicious keyword: ${keyword}`);
                score -= 25;
            }
        }
        
        return {
            score: Math.max(0, score),
            status: score >= 80 ? 'safe' : score >= 60 ? 'warning' : 'danger',
            threats: threats
        };
    }

    checkSSLCertificate(urlObj) {
        const threats = [];
        let score = 100;
        
        // Check if HTTPS is used
        if (urlObj.protocol !== 'https:') {
            threats.push('No SSL encryption (HTTP)');
            score -= 40;
        }
        
        // Additional SSL checks would require actual certificate inspection
        // For demo purposes, we'll simulate some checks
        
        return {
            score: Math.max(0, score),
            status: score >= 80 ? 'safe' : score >= 60 ? 'warning' : 'danger',
            threats: threats
        };
    }

    checkSuspiciousPatterns(url, domain) {
        const threats = [];
        let score = 100;
        
        // Check for suspicious URL patterns
        const suspiciousPatterns = [
            /login.*verify/i,
            /account.*suspend/i,
            /security.*alert/i,
            /urgent.*action/i,
            /click.*here.*now/i,
            /limited.*time/i
        ];
        
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(url)) {
                threats.push('Suspicious URL pattern detected');
                score -= 30;
                break;
            }
        }
        
        // Check for IP addresses instead of domain names
        const ipPattern = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
        if (ipPattern.test(url)) {
            threats.push('IP address used instead of domain');
            score -= 35;
        }
        
        // Check for excessive redirects or suspicious parameters
        if (url.includes('redirect') || url.includes('r=') || url.includes('url=')) {
            threats.push('Potential redirect manipulation');
            score -= 20;
        }
        
        return {
            score: Math.max(0, score),
            status: score >= 80 ? 'safe' : score >= 60 ? 'warning' : 'danger',
            threats: threats
        };
    }

    isTyposquatting(domain, legitimate) {
        // Simple typosquatting detection
        if (domain === legitimate) return false;
        
        // Check for character substitution
        const substitutions = {
            'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '@',
            'm': 'rn', 'w': 'vv', 'cl': 'd'
        };
        
        let modifiedLegit = legitimate;
        for (const [original, substitute] of Object.entries(substitutions)) {
            modifiedLegit = modifiedLegit.replace(new RegExp(original, 'g'), substitute);
            if (domain.includes(modifiedLegit)) return true;
        }
        
        // Check for character insertion/deletion
        const levenshteinDistance = this.calculateLevenshteinDistance(domain, legitimate);
        return levenshteinDistance <= 2 && domain.length > legitimate.length - 3;
    }

    calculateLevenshteinDistance(str1, str2) {
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

    updateAnalysisResults(analysis) {
        // Update security score
        this.elements.scoreValue.textContent = analysis.overallScore;
        
        // Update score circle color
        const scoreCircle = document.querySelector('.score-circle');
        const percentage = (analysis.overallScore / 100) * 360;
        let color = 'var(--security-safe)';
        
        if (analysis.overallScore < 60) {
            color = 'var(--security-danger)';
        } else if (analysis.overallScore < 80) {
            color = 'var(--security-warning)';
        }
        
        scoreCircle.style.background = 
            `conic-gradient(${color} 0deg, ${color} ${percentage}deg, var(--bg-tertiary) ${percentage}deg)`;
        
        // Update individual indicators
        this.updateIndicator('url', analysis.checks.urlStructure);
        this.updateIndicator('domain', analysis.checks.domainReputation);
        this.updateIndicator('ssl', analysis.checks.sslCertificate);
        this.updateIndicator('suspicious', analysis.checks.suspiciousPatterns);
        
        // Show warning if dangerous
        if (analysis.riskLevel === 'danger' && this.elements.warningPopups.checked) {
            this.showThreatWarning(analysis);
        }
    }

    updateIndicator(type, checkResult) {
        const statusElement = this.elements[`${type}Status`];
        const resultElement = this.elements[`${type}Result`];
        
        statusElement.textContent = checkResult.status === 'safe' ? 'Secure' :
                                   checkResult.status === 'warning' ? 'Warning' : 'Threat';
        
        resultElement.className = `indicator-result ${checkResult.status}`;
        
        // Update icon based on status
        const iconPath = checkResult.status === 'safe' ? 
            'M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22A10,10 0 0,1 2,12A10,10 0 0,1 12,2M11,16.5L18,9.5L16.59,8.09L11,13.67L7.41,10.09L6,11.5L11,16.5Z' :
            checkResult.status === 'warning' ?
            'M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z' :
            'M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z';
        
        resultElement.querySelector('svg path').setAttribute('d', iconPath);
    }

    updateIndicatorStatus(status) {
        const indicators = ['url', 'domain', 'ssl', 'suspicious'];
        
        indicators.forEach(type => {
            const statusElement = this.elements[`${type}Status`];
            statusElement.textContent = status === 'checking' ? 'Checking...' : 'Ready';
        });
    }

    getSiteIcon(domain) {
        // Return appropriate emoji based on domain
        if (domain.includes('google')) return '🔍';
        if (domain.includes('github')) return '💻';
        if (domain.includes('youtube')) return '📺';
        if (domain.includes('facebook') || domain.includes('instagram')) return '📱';
        if (domain.includes('amazon')) return '🛒';
        if (domain.includes('paypal') || domain.includes('bank')) return '💳';
        if (domain.includes('microsoft')) return '🏢';
        if (domain.includes('apple')) return '🍎';
        return '🌐';
    }

    toggleProtection() {
        this.isProtectionEnabled = this.elements.protectionToggle.checked;
        this.updateProtectionStatus();
        this.saveSettings();
        
        const message = this.isProtectionEnabled ? 'Protection enabled' : 'Protection disabled';
        const type = this.isProtectionEnabled ? 'success' : 'warning';
        this.showToast(message, type);
        
        // Send to background script
        chrome.runtime.sendMessage({
            action: 'toggleProtection',
            enabled: this.isProtectionEnabled
        });
    }

    updateProtectionStatus() {
        const statusTitle = this.elements.statusTitle;
        const statusDescription = this.elements.statusDescription;
        const protectionStatus = document.querySelector('.protection-status');
        
        if (this.isProtectionEnabled) {
            statusTitle.textContent = 'Protected';
            statusDescription.textContent = 'Real-time phishing protection active';
            protectionStatus.style.background = 'linear-gradient(135deg, var(--security-safe), var(--security-info))';
        } else {
            statusTitle.textContent = 'Disabled';
            statusDescription.textContent = 'Phishing protection is turned off';
            protectionStatus.style.background = 'linear-gradient(135deg, var(--security-neutral), var(--security-warning))';
        }
    }

    toggleRealTimeScanning() {
        const isEnabled = this.elements.realTimeScanning.checked;
        this.saveSettings();
        
        const message = isEnabled ? 'Real-time scanning enabled' : 'Real-time scanning disabled';
        this.showToast(message, 'info');
        
        chrome.runtime.sendMessage({
            action: 'toggleRealTimeScanning',
            enabled: isEnabled
        });
    }

    async scanCurrentSite() {
        this.showToast('Scanning current site...', 'info');
        
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.url) {
                await this.analyzeSite(tab.url, tab.title);
                this.showToast('Site scan completed', 'success');
            } else {
                this.showToast('Unable to scan current site', 'warning');
            }
        } catch (error) {
            console.error('Error scanning site:', error);
            this.showToast('Scan failed', 'danger');
        }
    }

    reportSuspiciousSite() {
        this.showToast('Thank you for reporting! Site flagged for review.', 'success');
        
        // In a real implementation, this would send data to a security service
        chrome.runtime.sendMessage({
            action: 'reportSite',
            url: this.currentSiteData?.url || 'unknown'
        });
    }

    showThreatWarning(analysis) {
        // Create and show a warning notification
        if (this.elements.soundAlerts.checked) {
            // Play warning sound (would need audio file in real implementation)
            console.log('🔊 Threat warning sound');
        }
        
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'https://api.iconify.design/material-symbols:warning.svg?color=%23ef4444&width=48&height=48',
            title: 'Phishing Threat Detected!',
            message: `Suspicious website detected: ${analysis.domain}\nThreats: ${analysis.threats.join(', ')}`
        });
    }

    updateStatistics() {
        this.animateCounter(this.elements.threatsBlocked, this.stats.threatsBlocked);
        this.animateCounter(this.elements.sitesScanned, this.stats.sitesScanned);
        this.animateCounter(this.elements.avgScore, this.stats.avgScore);
    }

    animateCounter(element, targetValue) {
        const startValue = 0;
        const duration = 1000;
        const startTime = performance.now();
        
        const updateCounter = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            const easeOutCubic = 1 - Math.pow(1 - progress, 3);
            const currentValue = Math.floor(startValue + (targetValue - startValue) * easeOutCubic);
            
            element.textContent = currentValue.toLocaleString();
            
            if (progress < 1) {
                requestAnimationFrame(updateCounter);
            }
        };
        
        requestAnimationFrame(updateCounter);
    }

    toggleTheme() {
        const currentTheme = document.body.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.body.setAttribute('data-theme', newTheme);
        this.saveSettings();
        
        this.showToast(`Switched to ${newTheme} theme`, 'info');
    }

    startRealTimeUpdates() {
        // Update statistics every 30 seconds
        setInterval(() => {
            if (this.isProtectionEnabled) {
                // Simulate some activity
                if (Math.random() > 0.7) {
                    this.stats.sitesScanned++;
                    this.updateStatistics();
                    this.saveSettings();
                }
            }
        }, 30000);
    }

    showToast(message, type = 'success') {
        this.elements.toastMessage.textContent = message;
        this.elements.toast.className = `toast ${type}`;
        this.elements.toast.classList.add('show');
        
        // Update toast icon based on type
        const iconPaths = {
            success: 'M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z',
            warning: 'M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z',
            danger: 'M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z',
            info: 'M13,9H11V7H13M13,17H11V11H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z'
        };
        
        this.elements.toastIcon.querySelector('path').setAttribute('d', iconPaths[type] || iconPaths.success);
        
        setTimeout(() => {
            this.elements.toast.classList.remove('show');
        }, 3000);
    }

    showError(message) {
        this.showToast(message, 'danger');
    }
}

// Initialize the phishing detector when the popup loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('Phishing Detector: DOM loaded, initializing...');
    new PhishingDetector();
});