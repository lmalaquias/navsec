// content.js - Enhanced Vulnerability Scanner
// Author: Leandro Malaquias
// Extension: NavSec Vulnerability Scanner v1.4
(function() {
  'use strict';
  
  // Prevent multiple executions
  if (window.navSecScannerLoaded) {
    console.log('🔒 NavSec Scanner already loaded, skipping...');
    return;
  }
  window.navSecScannerLoaded = true;
  
  console.log('🔍 NavSec Vulnerability Scanner v1.4 STARTING on:', window.location.href);
  
  // Check if we should run on this page
  const currentUrl = window.location.href;
  if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://') ||
      currentUrl.startsWith('edge://') || currentUrl.startsWith('about:')) {
    console.log('NavSec: Skipping browser internal page');
    return;
  }
  
  // Configuration - More aggressive detection
  const SCANNER_CONFIG = {
    DETECTION_MODE: 'paranoid', // Changed to paranoid for better detection
    VERSION: '1.4',
    MIN_CONFIDENCE: 0.3, // Lowered threshold
    FALSE_POSITIVE_REDUCTION: false, // Disabled for now
    DEBUG_MODE: true // Added debug mode
  };

  class VulnerabilityScanner {
    constructor() {
      this.vulnerabilities = [];
      this.securityHeaders = null;
      this.tlsInfo = null;
      this.headerAnalysis = [];
      this.scanComplete = false;
      this.listenerAdded = false;
      
      console.log('📊 Scanner v1.4 initialized in PARANOID mode');
      
      // Listen for messages from background
      if (!window.navSecMessageListenerAdded) {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
          console.log('📨 Message received:', request.type);
          
          if (request.type === 'SECURITY_HEADERS_ANALYSIS') {
            console.log('📋 Header analysis received:', request.analysis?.length || 0, 'issues');
            this.securityHeaders = request.headers;
            this.tlsInfo = request.tls;
            this.headerAnalysis = request.analysis || [];
            this.processHeaderAnalysis();
            sendResponse({ success: true });
          } else if (request.type === 'START_SCAN' || request.immediate) {
            console.log('🚀 Scan request received');
            if (!this.scanComplete) {
              this.startScan();
            }
            sendResponse({ success: true, scanning: true });
          }
          return true;
        });
        window.navSecMessageListenerAdded = true;
      }
      
      // Force immediate start
      this.forceStart();
    }
    
    forceStart() {
      console.log('⚡ Force starting scan...');
      
      // Start immediately
      this.startScan();
      
      // Request headers from background
      this.requestHeaderAnalysis();
      
      // Also try after DOM is ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          console.log('📄 DOM loaded, running additional checks...');
          this.performDOMChecks();
        });
      } else {
        this.performDOMChecks();
      }
      
      // Final check after window load
      window.addEventListener('load', () => {
        console.log('🌐 Window loaded, final scan...');
        setTimeout(() => {
          this.finalScan();
        }, 1000);
      });
    }
    
    requestHeaderAnalysis() {
      console.log('📡 Requesting header analysis from background...');
      chrome.runtime.sendMessage({ 
        type: 'REQUEST_HEADERS',
        url: window.location.href 
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('❌ Failed to request headers:', chrome.runtime.lastError);
        } else {
          console.log('✅ Header request sent');
        }
      });
    }
    
    startScan() {
      if (this.scanComplete) {
        console.log('⏭️ Scan already completed');
        return;
      }
      
      console.log('🔍 Starting comprehensive vulnerability scan...');
      console.log('📊 Config:', SCANNER_CONFIG);
      
      try {
        // Core security checks
        this.checkHTTPS();
        this.checkMixedContent();
        this.checkInsecureForms();
        
        // Critical vulnerability checks
        this.checkXSSVulnerabilities();
        this.checkSQLInjection();
        this.checkCookieSecurity();
        
        // Authentication & Sessions
        this.checkAuthentication();
        this.checkSessionManagement();
        
        // Data exposure
        this.checkSensitiveDataExposure();
        this.checkLocalStorageIssues();
        
        // Infrastructure
        this.checkOutdatedLibraries();
        this.checkCSP();
        this.checkCORS();
        
        console.log(`✅ Initial scan complete: ${this.vulnerabilities.length} issues found`);
        
        // Send initial results
        this.sendResults();
        
      } catch (error) {
        console.error('❌ Error during scan:', error);
        this.sendResults();
      }
    }
    
    performDOMChecks() {
      console.log('🔍 Performing DOM-based checks...');
      
      // Additional DOM-dependent checks
      this.checkFormValidation();
      this.checkIframeIssues();
      this.checkExternalResources();
      this.checkJavaScriptIssues();
      this.checkComments();
      
      // Send updated results
      this.sendResults();
    }
    
    finalScan() {
      console.log('🔍 Final scan pass...');
      
      // Check for dynamic content
      this.checkDynamicContent();
      this.checkWebSockets();
      this.checkAPIEndpoints();
      
      // Mark as complete
      this.scanComplete = true;
      
      // Send final results
      this.sendResults();
    }
    
    // Enhanced HTTPS check
    checkHTTPS() {
      console.log('🔒 Checking HTTPS...');
      
      if (window.location.protocol !== 'https:') {
        this.addVulnerability({
          type: 'NO_HTTPS',
          severity: 'critical',
          title: 'Site not using HTTPS',
          description: 'All data transmitted to/from this site is unencrypted and can be intercepted',
          recommendation: 'Implement HTTPS with a valid SSL certificate',
          evidence: `Protocol: ${window.location.protocol}`,
          confidence: 1.0
        });
        console.log('⚠️ HTTPS not enabled!');
      } else {
        console.log('✅ HTTPS enabled');
      }
    }
    
    // Enhanced XSS detection
    checkXSSVulnerabilities() {
      console.log('🔍 Checking for XSS vulnerabilities...');
      
      // Check URL parameters
      const urlParams = new URLSearchParams(window.location.search);
      let xssCount = 0;
      
      urlParams.forEach((value, key) => {
        // Check if parameter is reflected in page
        if (document.body && document.body.innerHTML.includes(value) && value.length > 2) {
          xssCount++;
          this.addVulnerability({
            type: 'REFLECTED_XSS',
            severity: 'high',
            title: 'Potential Reflected XSS',
            description: `URL parameter "${key}" is reflected in page content without apparent encoding`,
            recommendation: 'Implement proper output encoding for all user input',
            evidence: `Parameter: ${key}=${value.substring(0, 50)}`,
            confidence: 0.7
          });
        }
        
        // Check for dangerous patterns
        if (/<script|javascript:|on\w+=/i.test(value)) {
          this.addVulnerability({
            type: 'XSS_PATTERN',
            severity: 'critical',
            title: 'Dangerous XSS pattern in URL',
            description: `URL parameter "${key}" contains potential XSS payload`,
            recommendation: 'Validate and sanitize all URL parameters',
            evidence: `Pattern found: ${value.substring(0, 100)}`,
            confidence: 0.9
          });
        }
      });
      
      // Check for unsafe inline scripts
      const inlineScripts = document.querySelectorAll('script:not([src])');
      if (inlineScripts.length > 0) {
        this.addVulnerability({
          type: 'INLINE_SCRIPTS',
          severity: 'medium',
          title: 'Inline JavaScript detected',
          description: `${inlineScripts.length} inline script(s) found which may be vulnerable to injection`,
          recommendation: 'Move JavaScript to external files and implement CSP',
          evidence: `${inlineScripts.length} inline script blocks`,
          confidence: 0.5
        });
      }
      
      // Check for dangerous event handlers
      const eventHandlers = document.querySelectorAll('[onclick], [onload], [onerror], [onmouseover], [onfocus], [onblur]');
      if (eventHandlers.length > 0) {
        this.addVulnerability({
          type: 'INLINE_EVENT_HANDLERS',
          severity: 'medium',
          title: 'Inline event handlers detected',
          description: 'Inline event handlers can be injection points for XSS',
          recommendation: 'Use addEventListener instead of inline event handlers',
          evidence: `${eventHandlers.length} inline event handler(s)`,
          confidence: 0.6
        });
      }
      
      console.log(`📊 XSS check complete: ${xssCount} potential issues`);
    }
    
    // Enhanced SQL Injection detection
    checkSQLInjection() {
      console.log('🔍 Checking for SQL Injection vulnerabilities...');
      
      // Check URL for SQL patterns
      const url = window.location.href;
      const sqlPatterns = [
        /(\?|&)id=\d+/i,
        /(\?|&)user=\w+/i,
        /(\?|&)product=\w+/i,
        /(\?|&)category=\w+/i,
        /(\?|&)search=/i,
        /(\?|&)q=/i
      ];
      
      let hasSQLParams = false;
      sqlPatterns.forEach(pattern => {
        if (pattern.test(url)) {
          hasSQLParams = true;
        }
      });
      
      if (hasSQLParams) {
        this.addVulnerability({
          type: 'SQL_INJECTION_RISK',
          severity: 'medium',
          title: 'Potential SQL Injection point',
          description: 'URL contains parameters commonly vulnerable to SQL injection',
          recommendation: 'Ensure all database queries use parameterized statements',
          evidence: `URL pattern detected`,
          confidence: 0.5
        });
      }
      
      // Check for SQL error messages
      const pageText = document.body ? document.body.innerText : '';
      const sqlErrors = [
        /SQL syntax.*MySQL/i,
        /Warning.*mysql_/i,
        /MySQLSyntaxErrorException/i,
        /PostgreSQL.*ERROR/i,
        /ORA-\d{5}/,
        /SQLServer.*Error/i,
        /Microsoft.*ODBC.*SQL/i,
        /com\.mysql\.jdbc/i,
        /SqlException/i
      ];
      
      sqlErrors.forEach(pattern => {
        if (pattern.test(pageText)) {
          this.addVulnerability({
            type: 'SQL_ERROR_EXPOSED',
            severity: 'critical',
            title: 'SQL error message exposed',
            description: 'Database error messages are being displayed to users',
            recommendation: 'Implement proper error handling and never expose database errors',
            evidence: 'SQL error pattern detected in page',
            confidence: 0.9
          });
        }
      });
      
      // Check forms
      const forms = document.querySelectorAll('form');
      forms.forEach(form => {
        const inputs = form.querySelectorAll('input[type="text"], input[type="search"], textarea');
        if (inputs.length > 0 && !form.getAttribute('data-validated')) {
          this.addVulnerability({
            type: 'UNVALIDATED_INPUT',
            severity: 'medium',
            title: 'Form inputs may lack validation',
            description: 'Forms should validate and sanitize all user input',
            recommendation: 'Implement client and server-side input validation',
            evidence: `Form with ${inputs.length} input field(s)`,
            confidence: 0.4
          });
        }
      });
    }
    
    // Enhanced Cookie Security Check
    checkCookieSecurity() {
      console.log('🍪 Checking cookie security...');
      
      if (document.cookie) {
        const cookies = document.cookie.split(';');
        
        // Check for session cookies without HttpOnly (we can see them in JS)
        cookies.forEach(cookie => {
          const [name, value] = cookie.trim().split('=');
          
          if (name && (name.toLowerCase().includes('session') || 
                      name.toLowerCase().includes('token') ||
                      name.toLowerCase().includes('auth'))) {
            this.addVulnerability({
              type: 'COOKIE_NO_HTTPONLY',
              severity: 'high',
              title: 'Session cookie accessible via JavaScript',
              description: `Cookie "${name}" can be accessed by JavaScript (missing HttpOnly flag)`,
              recommendation: 'Set HttpOnly flag on all session cookies',
              evidence: `Cookie: ${name}`,
              confidence: 0.8
            });
          }
        });
        
        // Check for cookies on HTTP
        if (window.location.protocol === 'http:' && cookies.length > 0) {
          this.addVulnerability({
            type: 'COOKIES_OVER_HTTP',
            severity: 'critical',
            title: 'Cookies transmitted over HTTP',
            description: 'Cookies are being sent without encryption',
            recommendation: 'Use HTTPS and set Secure flag on all cookies',
            evidence: `${cookies.length} cookie(s) found`,
            confidence: 1.0
          });
        }
      }
    }
    
    // Check for mixed content
    checkMixedContent() {
      console.log('🔍 Checking for mixed content...');
      
      if (window.location.protocol === 'https:') {
        // Check scripts
        const httpScripts = document.querySelectorAll('script[src^="http://"]');
        if (httpScripts.length > 0) {
          this.addVulnerability({
            type: 'MIXED_CONTENT_SCRIPTS',
            severity: 'critical',
            title: 'Mixed content: Scripts loaded over HTTP',
            description: 'Scripts loaded over HTTP can be intercepted and modified',
            recommendation: 'Load all scripts over HTTPS',
            evidence: `${httpScripts.length} insecure script(s)`,
            confidence: 1.0
          });
        }
        
        // Check styles
        const httpStyles = document.querySelectorAll('link[href^="http://"]');
        if (httpStyles.length > 0) {
          this.addVulnerability({
            type: 'MIXED_CONTENT_STYLES',
            severity: 'high',
            title: 'Mixed content: Stylesheets loaded over HTTP',
            description: 'Stylesheets loaded over HTTP can be modified by attackers',
            recommendation: 'Load all stylesheets over HTTPS',
            evidence: `${httpStyles.length} insecure stylesheet(s)`,
            confidence: 0.9
          });
        }
        
        // Check forms
        const httpForms = document.querySelectorAll('form[action^="http://"]');
        if (httpForms.length > 0) {
          this.addVulnerability({
            type: 'INSECURE_FORM_ACTION',
            severity: 'critical',
            title: 'Form submits to HTTP',
            description: 'Form data will be sent without encryption',
            recommendation: 'Submit all forms over HTTPS',
            evidence: `${httpForms.length} insecure form(s)`,
            confidence: 1.0
          });
        }
      }
    }
    
    // Check for insecure forms
    checkInsecureForms() {
      console.log('📝 Checking form security...');
      
      const forms = document.querySelectorAll('form');
      
      forms.forEach((form, index) => {
        // Check for password fields without HTTPS
        const passwordFields = form.querySelectorAll('input[type="password"]');
        if (passwordFields.length > 0 && window.location.protocol !== 'https:') {
          this.addVulnerability({
            type: 'PASSWORD_OVER_HTTP',
            severity: 'critical',
            title: 'Password field on non-HTTPS page',
            description: 'Passwords will be transmitted without encryption',
            recommendation: 'Never collect passwords without HTTPS',
            evidence: `Form #${index + 1} has password field(s)`,
            confidence: 1.0
          });
        }
        
        // Check for autocomplete on sensitive fields
        passwordFields.forEach(field => {
          if (field.autocomplete !== 'off' && field.autocomplete !== 'new-password') {
            this.addVulnerability({
              type: 'PASSWORD_AUTOCOMPLETE',
              severity: 'medium',
              title: 'Password field allows autocomplete',
              description: 'Password fields should disable autocomplete for security',
              recommendation: 'Set autocomplete="new-password" on password fields',
              evidence: `Password field with autocomplete enabled`,
              confidence: 0.7
            });
          }
        });
        
        // Check for missing CSRF protection
        const csrfToken = form.querySelector('input[name*="csrf"], input[name*="token"], input[type="hidden"][name*="authenticity"]');
        if (!csrfToken && form.method && form.method.toUpperCase() === 'POST') {
          this.addVulnerability({
            type: 'MISSING_CSRF_TOKEN',
            severity: 'high',
            title: 'Form may lack CSRF protection',
            description: 'POST form without visible CSRF token',
            recommendation: 'Implement CSRF tokens for all state-changing operations',
            evidence: `POST form without CSRF token`,
            confidence: 0.6
          });
        }
      });
    }
    
    // Check authentication issues
    checkAuthentication() {
      console.log('🔐 Checking authentication...');
      
      // Check for basic auth in URL
      if (window.location.href.includes('@')) {
        this.addVulnerability({
          type: 'BASIC_AUTH_IN_URL',
          severity: 'critical',
          title: 'Credentials in URL',
          description: 'Username/password visible in URL',
          recommendation: 'Never put credentials in URLs',
          evidence: 'URL contains @ character',
          confidence: 0.9
        });
      }
      
      // Check for common authentication endpoints
      const authEndpoints = ['login', 'signin', 'auth', 'authenticate'];
      const currentPath = window.location.pathname.toLowerCase();
      
      authEndpoints.forEach(endpoint => {
        if (currentPath.includes(endpoint) && window.location.protocol !== 'https:') {
          this.addVulnerability({
            type: 'AUTH_OVER_HTTP',
            severity: 'critical',
            title: 'Authentication page without HTTPS',
            description: 'Login credentials will be sent unencrypted',
            recommendation: 'Always use HTTPS for authentication',
            evidence: `Auth endpoint: ${endpoint}`,
            confidence: 0.9
          });
        }
      });
    }
    
    // Check session management
    checkSessionManagement() {
      console.log('🔑 Checking session management...');
      
      // Check for session info in URL
      const url = window.location.href;
      const sessionPatterns = [
        /[?&]session_?id=/i,
        /[?&]sid=/i,
        /[?&]phpsessid=/i,
        /[?&]jsessionid=/i,
        /[?&]aspsessionid=/i
      ];
      
      sessionPatterns.forEach(pattern => {
        if (pattern.test(url)) {
          this.addVulnerability({
            type: 'SESSION_IN_URL',
            severity: 'high',
            title: 'Session ID in URL',
            description: 'Session identifiers in URLs can be leaked through referrer headers',
            recommendation: 'Store session IDs in cookies with HttpOnly and Secure flags',
            evidence: 'Session parameter in URL',
            confidence: 0.8
          });
        }
      });
    }
    
    // Check for sensitive data exposure
    checkSensitiveDataExposure() {
      console.log('🔍 Checking for sensitive data exposure...');
      
      const pageText = document.body ? document.body.innerText : '';
      
      // Check for exposed API keys
      const apiKeyPatterns = [
        /api[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9]{20,}/gi,
        /secret[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9]{20,}/gi,
        /access[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9]{20,}/gi,
        /AIza[0-9A-Za-z\-_]{35}/g, // Google API
        /sk_live_[0-9a-zA-Z]{24}/g, // Stripe
        /AKIA[0-9A-Z]{16}/g // AWS
      ];
      
      apiKeyPatterns.forEach(pattern => {
        const matches = pageText.match(pattern) || [];
        if (matches.length > 0) {
          this.addVulnerability({
            type: 'API_KEY_EXPOSED',
            severity: 'critical',
            title: 'API key exposed in page',
            description: 'API keys should never be exposed in client-side code',
            recommendation: 'Move API keys to server-side configuration',
            evidence: `Found ${matches.length} potential API key(s)`,
            confidence: 0.8
          });
        }
      });
      
      // Check for exposed emails
      const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const emails = pageText.match(emailPattern) || [];
      if (emails.length > 10) {
        this.addVulnerability({
          type: 'EMAIL_HARVESTING',
          severity: 'low',
          title: 'Multiple email addresses exposed',
          description: `${emails.length} email addresses found that could be harvested by bots`,
          recommendation: 'Obfuscate email addresses or use contact forms',
          evidence: `${emails.length} email(s) found`,
          confidence: 0.5
        });
      }
      
      // Check for server info
      const serverPatterns = [
        /Apache\/[\d.]+/i,
        /nginx\/[\d.]+/i,
        /PHP\/[\d.]+/i,
        /ASP\.NET Version:[\d.]+/i,
        /X-Powered-By:/i
      ];
      
      serverPatterns.forEach(pattern => {
        if (pattern.test(pageText)) {
          this.addVulnerability({
            type: 'SERVER_INFO_EXPOSED',
            severity: 'low',
            title: 'Server information exposed',
            description: 'Server version information can help attackers identify vulnerabilities',
            recommendation: 'Remove server version information from responses',
            evidence: 'Server signature found',
            confidence: 0.6
          });
        }
      });
    }
    
    // Check localStorage/sessionStorage
    checkLocalStorageIssues() {
      console.log('💾 Checking browser storage...');
      
      try {
        // Check localStorage
        if (localStorage.length > 0) {
          const sensitiveKeys = ['password', 'token', 'key', 'secret', 'api', 'auth', 'session', 'credit', 'card'];
          
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);
            
            sensitiveKeys.forEach(sensitive => {
              if (key.toLowerCase().includes(sensitive)) {
                this.addVulnerability({
                  type: 'SENSITIVE_DATA_LOCALSTORAGE',
                  severity: 'high',
                  title: 'Sensitive data in localStorage',
                  description: `Potentially sensitive data found in localStorage key: "${key}"`,
                  recommendation: 'Never store sensitive data in localStorage',
                  evidence: `Key: ${key}`,
                  confidence: 0.7
                });
              }
            });
            
            // Check for JWT tokens
            if (value && value.match(/^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/)) {
              this.addVulnerability({
                type: 'JWT_IN_LOCALSTORAGE',
                severity: 'high',
                title: 'JWT token in localStorage',
                description: 'JWT tokens in localStorage are vulnerable to XSS attacks',
                recommendation: 'Store tokens in httpOnly cookies instead',
                evidence: `JWT found in key: ${key}`,
                confidence: 0.9
              });
            }
          }
        }
        
        // Check sessionStorage
        if (sessionStorage.length > 0) {
          const sensitiveKeys = ['password', 'token', 'key', 'secret', 'api', 'auth'];
          
          for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            
            sensitiveKeys.forEach(sensitive => {
              if (key.toLowerCase().includes(sensitive)) {
                this.addVulnerability({
                  type: 'SENSITIVE_DATA_SESSIONSTORAGE',
                  severity: 'medium',
                  title: 'Sensitive data in sessionStorage',
                  description: `Potentially sensitive data in sessionStorage key: "${key}"`,
                  recommendation: 'Avoid storing sensitive data in sessionStorage',
                  evidence: `Key: ${key}`,
                  confidence: 0.6
                });
              }
            });
          }
        }
      } catch (e) {
        console.log('⚠️ Cannot access browser storage');
      }
    }
    
    // Check outdated libraries
    checkOutdatedLibraries() {
      console.log('📚 Checking for outdated libraries...');
      
      // Common library patterns
      const libraries = {
        'jQuery': {
          pattern: /jquery[.-]?([\d.]+)/i,
          vulnerable: ['1.', '2.'],
          current: '3.6+'
        },
        'Angular': {
          pattern: /angular[.-]?([\d.]+)/i,
          vulnerable: ['1.'],
          current: '15+'
        },
        'React': {
          pattern: /react[.-]?([\d.]+)/i,
          vulnerable: ['15.', '16.'],
          current: '18+'
        },
        'Bootstrap': {
          pattern: /bootstrap[.-]?([\d.]+)/i,
          vulnerable: ['2.', '3.'],
          current: '5+'
        }
      };
      
      // Check script sources
      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        const src = script.src;
        
        Object.entries(libraries).forEach(([name, lib]) => {
          const match = src.match(lib.pattern);
          if (match && match[1]) {
            const version = match[1];
            const isVulnerable = lib.vulnerable.some(v => version.startsWith(v));
            
            if (isVulnerable) {
              this.addVulnerability({
                type: 'OUTDATED_LIBRARY',
                severity: 'medium',
                title: `Outdated ${name} library`,
                description: `Using ${name} version ${version} which may have known vulnerabilities`,
                recommendation: `Update to ${name} ${lib.current}`,
                evidence: `Version ${version} detected`,
                confidence: 0.7
              });
            }
          }
        });
      });
      
      // Check for old jQuery globally
      if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) {
        const version = window.jQuery.fn.jquery;
        if (version.startsWith('1.') || version.startsWith('2.')) {
          this.addVulnerability({
            type: 'OUTDATED_JQUERY',
            severity: 'medium',
            title: 'Outdated jQuery version',
            description: `jQuery ${version} has known security vulnerabilities`,
            recommendation: 'Update to jQuery 3.6 or later',
            evidence: `jQuery ${version}`,
            confidence: 0.9
          });
        }
      }
    }
    
    // Check CSP
    checkCSP() {
      console.log('🛡️ Checking Content Security Policy...');
      
      const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      
      if (!cspMeta && !this.securityHeaders?.['content-security-policy']) {
        this.addVulnerability({
          type: 'MISSING_CSP',
          severity: 'medium',
          title: 'Missing Content Security Policy',
          description: 'No CSP header found to prevent XSS attacks',
          recommendation: 'Implement a strict Content Security Policy',
          evidence: 'No CSP meta tag or header',
          confidence: 0.8
        });
      } else if (cspMeta) {
        const csp = cspMeta.content;
        
        // Check for unsafe directives
        if (csp.includes('unsafe-inline')) {
          this.addVulnerability({
            type: 'CSP_UNSAFE_INLINE',
            severity: 'medium',
            title: 'CSP allows unsafe-inline',
            description: 'unsafe-inline in CSP weakens XSS protection',
            recommendation: 'Remove unsafe-inline and use nonces or hashes',
            evidence: 'unsafe-inline directive found',
            confidence: 0.8
          });
        }
        
        if (csp.includes('unsafe-eval')) {
          this.addVulnerability({
            type: 'CSP_UNSAFE_EVAL',
            severity: 'medium',
            title: 'CSP allows unsafe-eval',
            description: 'unsafe-eval allows code injection attacks',
            recommendation: 'Remove unsafe-eval from CSP',
            evidence: 'unsafe-eval directive found',
            confidence: 0.8
          });
        }
      }
    }
    
    // Check CORS
    checkCORS() {
      console.log('🌐 Checking CORS configuration...');
      
      // Check for wildcard CORS
      const scripts = document.querySelectorAll('script');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('Access-Control-Allow-Origin: *') || 
            content.includes('"Access-Control-Allow-Origin":"*"')) {
          this.addVulnerability({
            type: 'CORS_WILDCARD',
            severity: 'medium',
            title: 'Wildcard CORS configuration detected',
            description: 'Allowing all origins can lead to data theft',
            recommendation: 'Specify allowed origins explicitly',
            evidence: 'Wildcard CORS pattern found',
            confidence: 0.6
          });
        }
      });
    }
    
    // Additional DOM checks
    checkFormValidation() {
      console.log('📝 Checking form validation...');
      
      const forms = document.querySelectorAll('form');
      forms.forEach((form, index) => {
        const inputs = form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])');
        let hasValidation = false;
        
        inputs.forEach(input => {
          if (input.required || input.pattern || input.minLength || input.maxLength) {
            hasValidation = true;
          }
        });
        
        if (inputs.length > 0 && !hasValidation) {
          this.addVulnerability({
            type: 'NO_CLIENT_VALIDATION',
            severity: 'low',
            title: 'Form lacks client-side validation',
            description: `Form #${index + 1} has no visible validation attributes`,
            recommendation: 'Add client-side validation for better UX and initial security',
            evidence: `${inputs.length} input(s) without validation`,
            confidence: 0.4
          });
        }
      });
    }
    
    checkIframeIssues() {
      console.log('🖼️ Checking iframes...');
      
      const iframes = document.querySelectorAll('iframe');
      iframes.forEach((iframe, index) => {
        // Check for missing sandbox
        if (!iframe.sandbox || iframe.sandbox.length === 0) {
          this.addVulnerability({
            type: 'IFRAME_NO_SANDBOX',
            severity: 'medium',
            title: 'Iframe without sandbox attribute',
            description: 'Iframes should use sandbox attribute to limit capabilities',
            recommendation: 'Add sandbox attribute to all iframes',
            evidence: `Iframe #${index + 1}: ${iframe.src || 'inline'}`,
            confidence: 0.6
          });
        }
        
        // Check for HTTP iframe on HTTPS page
        if (window.location.protocol === 'https:' && iframe.src && iframe.src.startsWith('http://')) {
          this.addVulnerability({
            type: 'MIXED_CONTENT_IFRAME',
            severity: 'high',
            title: 'Iframe loaded over HTTP',
            description: 'Iframe content loaded without encryption',
            recommendation: 'Load all iframes over HTTPS',
            evidence: `Iframe src: ${iframe.src}`,
            confidence: 0.9
          });
        }
      });
    }
    
    checkExternalResources() {
      console.log('🔗 Checking external resources...');
      
      // Check for resources from suspicious domains
      const resources = [...document.querySelectorAll('script[src], link[href], img[src], iframe[src]')];
      const suspiciousDomains = [];
      
      resources.forEach(resource => {
        const url = resource.src || resource.href;
        if (url && !url.startsWith('/') && !url.startsWith(window.location.origin)) {
          try {
            const domain = new URL(url).hostname;
            
            // Check for IP addresses
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
              suspiciousDomains.push(domain);
              this.addVulnerability({
                type: 'RESOURCE_FROM_IP',
                severity: 'medium',
                title: 'Resource loaded from IP address',
                description: `Loading resources from IP addresses instead of domains is suspicious`,
                recommendation: 'Use proper domain names for all resources',
                evidence: `IP: ${domain}`,
                confidence: 0.7
              });
            }
          } catch (e) {
            // Invalid URL
          }
        }
      });
    }
    
    checkJavaScriptIssues() {
      console.log('📜 Checking JavaScript issues...');
      
      // Check for eval usage
      const scripts = document.querySelectorAll('script');
      scripts.forEach(script => {
        const content = script.textContent || '';
        
        if (content.includes('eval(')) {
          this.addVulnerability({
            type: 'EVAL_USAGE',
            severity: 'high',
            title: 'eval() function detected',
            description: 'eval() can execute arbitrary code and is a security risk',
            recommendation: 'Avoid using eval(), use JSON.parse() or other safe alternatives',
            evidence: 'eval() found in JavaScript',
            confidence: 0.8
          });
        }
        
        if (content.includes('document.write(')) {
          this.addVulnerability({
            type: 'DOCUMENT_WRITE',
            severity: 'medium',
            title: 'document.write() detected',
            description: 'document.write() can be used for DOM-based XSS',
            recommendation: 'Use safe DOM manipulation methods instead',
            evidence: 'document.write() found',
            confidence: 0.6
          });
        }
        
        if (content.includes('.innerHTML') && content.includes('=')) {
          this.addVulnerability({
            type: 'UNSAFE_INNERHTML',
            severity: 'medium',
            title: 'innerHTML assignment detected',
            description: 'Direct innerHTML assignment can lead to XSS',
            recommendation: 'Use textContent or safe templating',
            evidence: 'innerHTML assignment found',
            confidence: 0.5
          });
        }
      });
    }
    
    checkComments() {
      console.log('💬 Checking HTML comments...');
      
      const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_COMMENT,
        null,
        false
      );
      
      let commentCount = 0;
      let suspiciousComments = [];
      
      while (walker.nextNode()) {
        commentCount++;
        const comment = walker.currentNode.nodeValue;
        
        // Check for sensitive info in comments
        if (comment.match(/todo|fixme|hack|bug|password|key|token|secret/i)) {
          suspiciousComments.push(comment.substring(0, 100));
        }
      }
      
      if (suspiciousComments.length > 0) {
        this.addVulnerability({
          type: 'SENSITIVE_COMMENTS',
          severity: 'low',
          title: 'Sensitive information in HTML comments',
          description: 'HTML comments may contain sensitive information',
          recommendation: 'Remove all HTML comments from production code',
          evidence: `${suspiciousComments.length} suspicious comment(s)`,
          confidence: 0.5
        });
      }
      
      if (commentCount > 20) {
        this.addVulnerability({
          type: 'EXCESSIVE_COMMENTS',
          severity: 'info',
          title: 'Excessive HTML comments',
          description: `${commentCount} HTML comments found which may leak information`,
          recommendation: 'Minimize or remove HTML comments in production',
          evidence: `${commentCount} total comments`,
          confidence: 0.3
        });
      }
    }
    
    checkDynamicContent() {
      console.log('🔄 Checking dynamic content...');
      
      // Check for AJAX requests without HTTPS
      if (window.XMLHttpRequest) {
        const originalOpen = XMLHttpRequest.prototype.open;
        let httpRequests = 0;
        
        XMLHttpRequest.prototype.open = function(method, url) {
          if (url && url.startsWith('http://') && window.location.protocol === 'https:') {
            httpRequests++;
          }
          return originalOpen.apply(this, arguments);
        };
        
        // Wait a bit to see if any requests are made
        setTimeout(() => {
          if (httpRequests > 0) {
            this.addVulnerability({
              type: 'AJAX_OVER_HTTP',
              severity: 'high',
              title: 'AJAX requests over HTTP',
              description: 'AJAX requests are being made without encryption',
              recommendation: 'Use HTTPS for all AJAX requests',
              evidence: `${httpRequests} HTTP request(s) detected`,
              confidence: 0.8
            });
          }
        }, 2000);
      }
    }
    
    checkWebSockets() {
      console.log('🔌 Checking WebSockets...');
      
      // Check for insecure WebSocket connections
      const scripts = document.querySelectorAll('script');
      scripts.forEach(script => {
        const content = script.textContent || '';
        
        if (content.includes('ws://') && window.location.protocol === 'https:') {
          this.addVulnerability({
            type: 'INSECURE_WEBSOCKET',
            severity: 'high',
            title: 'Insecure WebSocket connection',
            description: 'WebSocket using ws:// instead of wss://',
            recommendation: 'Use wss:// for secure WebSocket connections',
            evidence: 'ws:// protocol detected',
            confidence: 0.7
          });
        }
      });
    }
    
    checkAPIEndpoints() {
      console.log('🔌 Checking API endpoints...');
      
      // Look for API endpoints in JavaScript
      const scripts = document.querySelectorAll('script');
      const apiPatterns = [
        /\/api\//i,
        /\/rest\//i,
        /\/graphql/i,
        /\/v\d+\//,
        /\.json/i
      ];
      
      scripts.forEach(script => {
        const content = script.textContent || '';
        
        apiPatterns.forEach(pattern => {
          if (pattern.test(content)) {
            // Check if API calls are made over HTTP
            if (content.includes('http://') && window.location.protocol === 'https:') {
              this.addVulnerability({
                type: 'API_OVER_HTTP',
                severity: 'high',
                title: 'API calls over HTTP detected',
                description: 'API endpoints being called without encryption',
                recommendation: 'Use HTTPS for all API calls',
                evidence: 'HTTP API pattern found',
                confidence: 0.6
              });
            }
          }
        });
      });
    }
    
    // Process header analysis from background
    processHeaderAnalysis() {
      console.log('📋 Processing header analysis...');
      
      if (this.headerAnalysis && this.headerAnalysis.length > 0) {
        this.headerAnalysis.forEach(vuln => {
          this.addVulnerability(vuln);
        });
        console.log(`✅ Added ${this.headerAnalysis.length} header vulnerabilities`);
      }
      
      // Send updated results
      this.sendResults();
    }
    
    // Add vulnerability with deduplication
    addVulnerability(vuln) {
      // Check for duplicates
      const isDuplicate = this.vulnerabilities.some(existing => 
        existing.type === vuln.type && 
        existing.title === vuln.title
      );
      
      if (!isDuplicate) {
        this.vulnerabilities.push({
          ...vuln,
          timestamp: Date.now(),
          url: window.location.href
        });
        
        console.log(`🚨 Found: ${vuln.title} [${vuln.severity}] (confidence: ${vuln.confidence || 'N/A'})`);
      }
    }
    
    // Calculate security score
    calculateSecurityScore() {
      let score = 100;
      
      const penalties = {
        critical: 25,
        high: 15,
        medium: 8,
        low: 3,
        info: 0
      };
      
      // Group vulnerabilities by type to avoid over-penalizing
      const grouped = {};
      this.vulnerabilities.forEach(vuln => {
        const key = vuln.type;
        if (!grouped[key]) {
          grouped[key] = vuln;
        }
      });
      
      Object.values(grouped).forEach(vuln => {
        const severity = vuln.severity || 'info';
        score -= penalties[severity] || 0;
      });
      
      return Math.max(0, Math.round(score));
    }
    
    // Send results to background
    sendResults() {
      const score = this.calculateSecurityScore();
      
      const results = {
        type: 'SCAN_COMPLETE',
        url: window.location.href,
        vulnerabilities: this.vulnerabilities,
        score: score,
        timestamp: Date.now()
      };
      
      console.log(`📤 Sending results: ${this.vulnerabilities.length} vulnerabilities, score: ${score}`);
      
      // Send to background
      chrome.runtime.sendMessage(results, (response) => {
        if (chrome.runtime.lastError) {
          console.error('❌ Failed to send results:', chrome.runtime.lastError);
          // Retry once
          setTimeout(() => {
            chrome.runtime.sendMessage(results);
          }, 1000);
        } else {
          console.log('✅ Results sent successfully');
        }
      });
    }
  }
  
  // Initialize scanner
  console.log('🚀 Initializing NavSec Scanner v1.4...');
  const scanner = new VulnerabilityScanner();
  window.navSecScanner = scanner; // For debugging
  
})();
