// Phishing Detector Content Script
// This script runs on all web pages to provide real-time protection

class PhishingContentScript {
    constructor() {
        this.isProtectionEnabled = true;
        this.currentAnalysis = null;
        this.warningOverlay = null;
        
        this.init();
    }

    async init() {
        // Get settings from storage
        await this.loadSettings();
        
        // Listen for messages from popup and background script
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
        });
        
        // Start monitoring if protection is enabled
        if (this.isProtectionEnabled) {
            this.startMonitoring();
        }
        
        // Only analyze page if it's not a trusted domain
        if (this.shouldAnalyzePage()) {
            this.analyzeCurrentPage();
        }
    }

    async loadSettings() {
        return new Promise((resolve) => {
            chrome.storage.sync.get({
                protectionEnabled: true,
                realTimeScanning: true,
                warningPopups: true,
                soundAlerts: false
            }, (settings) => {
                this.isProtectionEnabled = settings.protectionEnabled;
                this.realTimeScanning = settings.realTimeScanning;
                this.warningPopups = settings.warningPopups;
                this.soundAlerts = settings.soundAlerts;
                resolve();
            });
        });
    }

    shouldAnalyzePage() {
        const url = window.location.href;
        const hostname = window.location.hostname;
        
        // Skip analysis for trusted domains and internal pages
        const trustedDomains = [
            'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
            'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'amazon.com', 'netflix.com', 'spotify.com',
            'apple.com', 'microsoft.com', 'mozilla.org'
        ];
        
        // Skip chrome internal pages
        if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
            url.startsWith('moz-extension://') || url.startsWith('about:')) {
            return false;
        }
        
        // Skip trusted domains
        for (const domain of trustedDomains) {
            if (hostname.includes(domain)) {
                return false;
            }
        }
        
        return true;
    }

    handleMessage(message, sender, sendResponse) {
        switch (message.action) {
            case 'toggleProtection':
                this.isProtectionEnabled = message.enabled;
                if (this.isProtectionEnabled) {
                    this.startMonitoring();
                } else {
                    this.stopMonitoring();
                }
                break;
                
            case 'scanPage':
                this.analyzeCurrentPage();
                break;
                
            case 'getPageAnalysis':
                sendResponse(this.currentAnalysis);
                break;
        }
    }

    startMonitoring() {
        console.log('Phishing Detector: Starting real-time monitoring...');
        
        // Monitor for suspicious form submissions
        this.monitorForms();
        
        // Monitor for suspicious links
        this.monitorLinks();
        
        // Monitor for suspicious scripts
        this.monitorScripts();
        
        // Monitor for page changes
        this.monitorPageChanges();
    }

    stopMonitoring() {
        console.log('Phishing Detector: Stopping monitoring...');
        // Remove event listeners and cleanup
    }

    analyzeCurrentPage() {
        const url = window.location.href;
        const title = document.title;
        
        console.log('Phishing Detector: Analyzing page:', url);
        
        // Perform basic analysis
        const analysis = this.performPageAnalysis(url, title);
        this.currentAnalysis = analysis;
        
        // Send analysis to background script
        chrome.runtime.sendMessage({
            action: 'pageAnalyzed',
            url: url,
            analysis: analysis
        });
        
        // Show warning if dangerous
        if (analysis.riskLevel === 'danger' && this.warningPopups) {
            this.showWarningOverlay(analysis);
        }
    }

    performPageAnalysis(url, title) {
        const analysis = {
            url: url,
            title: title,
            timestamp: Date.now(),
            riskLevel: 'safe',
            threats: [],
            score: 100
        };

        // Check for suspicious page elements
        this.checkSuspiciousElements(analysis);
        
        // Check for phishing indicators in content
        this.checkPageContent(analysis);
        
        // Check for suspicious forms
        this.checkForms(analysis);
        
        // Calculate final risk level
        if (analysis.score < 60) {
            analysis.riskLevel = 'danger';
        } else if (analysis.score < 80) {
            analysis.riskLevel = 'warning';
        }
        
        return analysis;
    }

    checkSuspiciousElements(analysis) {
        // Check for hidden iframes (but be more specific)
        const hiddenIframes = document.querySelectorAll('iframe[style*="display:none"], iframe[style*="visibility:hidden"]');
        const suspiciousIframes = Array.from(hiddenIframes).filter(iframe => {
            // Only flag iframes that are truly suspicious (not legitimate tracking or analytics)
            const src = iframe.src || '';
            return src && !src.includes('google') && !src.includes('facebook') && 
                   !src.includes('instagram') && !src.includes('twitter') && 
                   !src.includes('youtube') && !src.includes('analytics');
        });
        
        if (suspiciousIframes.length > 0) {
            analysis.threats.push('Hidden iframe detected');
            analysis.score -= 30;
        }
        
        // Check for truly suspicious scripts (be much more specific)
        const scripts = document.querySelectorAll('script');
        scripts.forEach(script => {
            if (script.src) {
                const src = script.src.toLowerCase();
                // Only flag obviously malicious script sources
                if (src.startsWith('data:text/javascript') || 
                    src.startsWith('javascript:') ||
                    (src.startsWith('data:') && src.includes('eval(') || src.includes('document.write('))) {
                    analysis.threats.push('Suspicious script source');
                    analysis.score -= 25;
                }
            }
        });
        
        // Check for fake security badges (be more lenient)
        const images = document.querySelectorAll('img[alt*="secure" i], img[alt*="verified" i]');
        const suspiciousBadges = Array.from(images).filter(img => {
            const src = img.src.toLowerCase();
            // Only flag if it's clearly trying to impersonate known security companies
            return !src.includes('verisign') && !src.includes('norton') && 
                   !src.includes('mcafee') && !src.includes('ssl') &&
                   !src.includes('https') && src.includes('secure');
        });
        
        if (suspiciousBadges.length > 0) {
            analysis.threats.push('Fake security badge detected');
            analysis.score -= 20;
        }
    }

    checkPageContent(analysis) {
        const pageText = document.body.textContent.toLowerCase();
        
        // Check for urgent language
        const urgentPhrases = [
            'urgent action required',
            'account will be closed',
            'verify immediately',
            'suspended account',
            'click here now',
            'limited time offer',
            'act now'
        ];
        
        urgentPhrases.forEach(phrase => {
            if (pageText.includes(phrase)) {
                analysis.threats.push(`Urgent language detected: "${phrase}"`);
                analysis.score -= 15;
            }
        });
        
        // Check for spelling errors (simple check)
        const commonMisspellings = [
            'recieve', 'seperate', 'occured', 'neccessary', 'definately'
        ];
        
        commonMisspellings.forEach(misspelling => {
            if (pageText.includes(misspelling)) {
                analysis.threats.push('Spelling errors detected');
                analysis.score -= 10;
            }
        });
    }

    checkForms(analysis) {
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
            // Check for password fields without proper security
            const passwordFields = form.querySelectorAll('input[type="password"]');
            if (passwordFields.length > 0 && window.location.protocol !== 'https:') {
                analysis.threats.push('Password form on non-HTTPS page');
                analysis.score -= 40;
            }
            
            // Check for suspicious form actions
            if (form.action && (form.action.includes('data:') || form.action.includes('javascript:'))) {
                analysis.threats.push('Suspicious form action');
                analysis.score -= 35;
            }
            
            // Check for forms asking for sensitive information
            const inputs = form.querySelectorAll('input');
            inputs.forEach(input => {
                const placeholder = (input.placeholder || '').toLowerCase();
                const name = (input.name || '').toLowerCase();
                
                if (placeholder.includes('ssn') || placeholder.includes('social security') ||
                    name.includes('ssn') || name.includes('social')) {
                    analysis.threats.push('Form requesting SSN');
                    analysis.score -= 30;
                }
                
                if (placeholder.includes('credit card') || placeholder.includes('card number') ||
                    name.includes('credit') || name.includes('card')) {
                    analysis.threats.push('Form requesting credit card');
                    analysis.score -= 25;
                }
            });
        });
    }

    monitorForms() {
        document.addEventListener('submit', (event) => {
            if (!this.isProtectionEnabled) return;
            
            const form = event.target;
            if (this.isFormSuspicious(form)) {
                event.preventDefault();
                this.showFormWarning(form);
            }
        });
    }

    monitorLinks() {
        document.addEventListener('click', (event) => {
            if (!this.isProtectionEnabled) return;
            
            const link = event.target.closest('a');
            if (link && this.isLinkSuspicious(link)) {
                event.preventDefault();
                this.showLinkWarning(link);
            }
        });
    }

    monitorScripts() {
        // Monitor for dynamically added scripts
        const observer = new MutationObserver((mutations) => {
            if (!this.isProtectionEnabled) return;
            
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.tagName === 'SCRIPT' && this.isScriptSuspicious(node)) {
                        this.showScriptWarning(node);
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    monitorPageChanges() {
        // Monitor for suspicious page modifications
        const observer = new MutationObserver((mutations) => {
            if (!this.isProtectionEnabled) return;
            
            // Check if page is being modified suspiciously
            let suspiciousChanges = 0;
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 10) {
                    suspiciousChanges++;
                }
            });
            
            if (suspiciousChanges > 5) {
                console.warn('Phishing Detector: Suspicious page modifications detected');
            }
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    isFormSuspicious(form) {
        // Check if form is suspicious
        const action = form.action || '';
        const method = form.method || 'get';
        
        // Suspicious if posting to external domain
        if (method.toLowerCase() === 'post' && action.includes('://') && 
            !action.includes(window.location.hostname)) {
            return true;
        }
        
        return false;
    }

    isLinkSuspicious(link) {
        const href = link.href || '';
        const text = link.textContent || '';
        
        // Check for URL shorteners
        const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl'];
        if (shorteners.some(shortener => href.includes(shortener))) {
            return true;
        }
        
        // Check for misleading text
        if (text.toLowerCase().includes('click here') && href.includes('://')) {
            return true;
        }
        
        return false;
    }

    isScriptSuspicious(script) {
        const src = script.src || '';
        
        // Check for data URLs or javascript URLs
        if (src.startsWith('data:') || src.startsWith('javascript:')) {
            return true;
        }
        
        return false;
    }

    showWarningOverlay(analysis) {
        if (this.warningOverlay) {
            this.warningOverlay.remove();
        }
        
        this.warningOverlay = document.createElement('div');
        this.warningOverlay.innerHTML = `
            <div style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                z-index: 999999;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            ">
                <div style="
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    max-width: 500px;
                    text-align: center;
                    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                ">
                    <div style="color: #ef4444; font-size: 48px; margin-bottom: 20px;">⚠️</div>
                    <h2 style="color: #ef4444; margin: 0 0 15px 0;">Phishing Threat Detected!</h2>
                    <p style="color: #666; margin: 0 0 20px 0;">
                        This website appears to be suspicious and may be attempting to steal your personal information.
                    </p>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; text-align: left;">
                        <strong>Detected threats:</strong>
                        <ul style="margin: 10px 0 0 0; padding-left: 20px;">
                            ${analysis.threats.map(threat => `<li>${threat}</li>`).join('')}
                        </ul>
                    </div>
                    <div style="display: flex; gap: 10px; justify-content: center;">
                        <button id="phishing-warning-leave" style="
                            background: #ef4444;
                            color: white;
                            border: none;
                            padding: 10px 20px;
                            border-radius: 5px;
                            cursor: pointer;
                            font-weight: bold;
                        ">Leave This Site</button>
                        <button id="phishing-warning-continue" style="
                            background: #6b7280;
                            color: white;
                            border: none;
                            padding: 10px 20px;
                            border-radius: 5px;
                            cursor: pointer;
                        ">Continue Anyway</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(this.warningOverlay);
        
        // Add event listeners
        document.getElementById('phishing-warning-leave').addEventListener('click', () => {
            window.history.back();
        });
        
        document.getElementById('phishing-warning-continue').addEventListener('click', () => {
            this.warningOverlay.remove();
            this.warningOverlay = null;
        });
    }

    showFormWarning(form) {
        alert('Phishing Detector: This form appears suspicious and may be trying to steal your information. Please verify the website before submitting.');
    }

    showLinkWarning(link) {
        const proceed = confirm(`Phishing Detector: This link appears suspicious:\n${link.href}\n\nDo you want to continue?`);
        if (proceed) {
            window.open(link.href, '_blank');
        }
    }

    showScriptWarning(script) {
        console.warn('Phishing Detector: Suspicious script blocked:', script.src);
        script.remove();
    }
}

// Initialize content script
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new PhishingContentScript();
    });
} else {
    new PhishingContentScript();
}