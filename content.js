// content.js - Enhanced Vulnerability Scanner
// Author: Leandro Malaquias
// Extension: NavSec Vulnerability Scanner v1.3
(function() {
  'use strict';
  
  // Prevent multiple executions
  if (window.navSecScannerLoaded) {
    console.log('🔍 NavSec Scanner already loaded, skipping...');
    return;
  }
  window.navSecScannerLoaded = true;
  
  console.log('🔍 NavSec Vulnerability Scanner v1.3 STARTING on:', window.location.href);
  
  // Check if we should run on this page
  const currentUrl = window.location.href;
  if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://') ||
      currentUrl.startsWith('edge://') || currentUrl.startsWith('about:')) {
    console.log('NavSec: Skipping browser internal page');
    return;
  }
  
  // Configuration with balanced mode by default
  const SCANNER_CONFIG = {
    DETECTION_MODE: 'balanced', // 'balanced' or 'paranoid'
    VERSION: '1.3',
    MIN_CONFIDENCE: 0.6, // Minimum confidence to report in balanced mode
    FALSE_POSITIVE_REDUCTION: true
  };
  
  // False positive patterns to ignore
  const FALSE_POSITIVE_PATTERNS = {
    sql: [
      'select all pages',
      'select all items',
      'selected rows',
      'delete confirmation',
      'update your profile',
      'insert image',
      'drop down',
      'dropdown menu',
      'create account',
      'create new',
      'execute action'
    ],
    xss: [
      'redirect_to=/login',
      'redirect_to=/dashboard',
      'return_url=/',
      'callback_url=/',
      'next_page=/'
    ],
    localStorage: [
      'theme',
      'language',
      'preferences',
      'ui-state',
      'last-visited'
    ]
  };

  // ============= REGIONAL COMPLIANCE MODULE (keeping existing) =============
  // [Previous regional compliance code remains the same - lines 16-1265]
  // ... [keeping all the regional validation code unchanged]

  class VulnerabilityScanner {
    constructor() {
      this.vulnerabilities = [];
      this.securityHeaders = null;
      this.tlsInfo = null;
      this.headerAnalysis = [];
      this.scanComplete = false;
      this.listenerAdded = false;
      this.confidenceScores = new Map(); // Track confidence for each vulnerability
      
      console.log('Content: Scanner instance created v1.3 with false positive reduction');
      
      // Listen for scan trigger from background
      if (!window.navSecMessageListenerAdded) {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
          if (request.type === 'SECURITY_HEADERS_ANALYSIS') {
            console.log('Content: Received header analysis from background:', request);
            this.securityHeaders = request.headers;
            this.tlsInfo = request.tls;
            this.headerAnalysis = request.analysis || [];
            this.processHeaderAnalysis();
            sendResponse({ success: true });
          } else if (request.type === 'START_SCAN' && request.immediate) {
            console.log('Content: Received immediate scan request');
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
      console.log('Content: Force starting scan...');
      
      // Start immediately
      this.startScan();
      
      // Also try after DOM is ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          console.log('Content: DOM loaded, starting additional scan...');
          if (!this.scanComplete) {
            this.startScan();
          }
        });
      }
      
      // And try after window load
      if (document.readyState !== 'complete') {
        window.addEventListener('load', () => {
          console.log('Content: Window loaded, ensuring scan completion...');
          if (!this.scanComplete) {
            this.startScan();
          }
        });
      }
    }
    
    startScan() {
      if (this.scanComplete) {
        console.log('Content: Scan already completed, skipping');
        return;
      }
      
      console.log('Content: Starting comprehensive vulnerability analysis v1.3...');
      
      try {
        // Core security checks
        this.checkHTTPS();
        this.checkInsecureForms();
        this.checkMixedContent();
        this.checkOutdatedLibraries();
        this.checkCSP();
        this.checkExternalLinks();
        
        // XSS checks with improved detection
        this.checkXSSImproved();
        
        // Authentication checks
        this.checkBasicAuth();
        
        // SQL Injection checks with reduced false positives
        this.checkSQLInjectionImproved();
        
        // Additional security checks
        this.checkCookieSecurity();
        this.checkAPIsAndCORS();
        this.checkSubresourceIntegrity();
        this.checkSensitiveInformationImproved();
        this.checkCommentsForSensitiveInfo();
        this.checkWebSocketSecurity();
        this.checkIframeSecurity();
        this.checkAdvancedFormSecurity();
        this.checkMetaTagsSecurity();
        
        console.log(`Content: Comprehensive scan complete, found ${this.vulnerabilities.length} vulnerabilities`);
        
        // Mark as complete
        this.scanComplete = true;
        
        // Send results immediately
        this.sendResults();
        
        // Also send after a delay to ensure delivery
        setTimeout(() => {
          this.sendResults();
        }, 1000);
        
      } catch (error) {
        console.error('Content: Error during scan:', error);
        // Send results even if there's an error
        this.scanComplete = true;
        this.sendResults();
      }
    }

    // Calculate confidence score for a finding
    calculateConfidence(type, evidence, context = {}) {
      let confidence = 0.5; // Base confidence
      
      // Adjust based on type
      if (type.includes('CRITICAL') || type.includes('SQL_ERROR')) {
        confidence += 0.3;
      } else if (type.includes('HIGH')) {
        confidence += 0.2;
      }
      
      // Adjust based on evidence quality
      if (evidence && evidence.length > 50) {
        confidence += 0.1;
      }
      
      // Specific adjustments
      if (context.multipleInstances) {
        confidence += 0.15;
      }
      
      if (context.validated) {
        confidence += 0.2;
      }
      
      if (context.falsePositiveRisk) {
        confidence -= 0.3;
      }
      
      return Math.min(Math.max(confidence, 0), 1);
    }

    // Check if text is likely UI text (false positive)
    isUIText(text) {
      if (!text) return false;
      
      const lowerText = text.toLowerCase();
      return FALSE_POSITIVE_PATTERNS.sql.some(pattern => 
        lowerText.includes(pattern)
      );
    }

    // Improved XSS detection with fewer false positives
    checkXSSImproved() {
      try {
        // Check URL parameters for potential XSS
        const urlParams = new URLSearchParams(window.location.search);
        let xssFound = false;
        
        urlParams.forEach((value, key) => {
          // Skip if too short or common false positive parameters
          if (value.length < 3) return;
          
          // Check for common safe redirect patterns
          const isSafeRedirect = FALSE_POSITIVE_PATTERNS.xss.some(pattern => 
            value.toLowerCase().startsWith(pattern)
          );
          
          if (isSafeRedirect) return;
          
          // Check if value is actually reflected without encoding
          const decoded = decodeURIComponent(value);
          
          // Only flag if contains actual dangerous patterns AND is reflected
          const hasScriptPattern = /<script|javascript:|on\w+=/i.test(decoded);
          const isReflected = document.body && document.body.innerHTML.includes(value);
          
          if (hasScriptPattern && isReflected && !xssFound) {
            const confidence = this.calculateConfidence('XSS', value, {
              validated: true
            });
            
            if (SCANNER_CONFIG.DETECTION_MODE === 'balanced' && confidence < SCANNER_CONFIG.MIN_CONFIDENCE) {
              return;
            }
            
            this.addVulnerability({
              type: 'REFLECTED_XSS_PARAM',
              severity: 'critical',
              title: 'Confirmed Reflected XSS in URL parameter',
              description: `URL parameter "${key}" contains script patterns and is reflected in page`,
              recommendation: 'Implement proper input validation and output encoding',
              evidence: `Parameter: ${key}=${value.substring(0, 100)}...`,
              payload: value,
              parameterName: key,
              context: 'URL parameter reflection',
              confidence: confidence
            });
            xssFound = true;
          } else if (isReflected && value.length > 10 && !xssFound) {
            // Lower severity for reflection without script patterns
            const confidence = this.calculateConfidence('XSS', value, {
              falsePositiveRisk: true
            });
            
            if (SCANNER_CONFIG.DETECTION_MODE === 'balanced' && confidence < SCANNER_CONFIG.MIN_CONFIDENCE) {
              return;
            }
            
            this.addVulnerability({
              type: 'PARAMETER_REFLECTION',
              severity: 'medium',
              title: 'URL parameter reflected in page',
              description: `URL parameter "${key}" is reflected in page content`,
              recommendation: 'Ensure proper output encoding is applied',
              evidence: `Parameter: ${key}`,
              confidence: confidence
            });
            xssFound = true;
          }
        });
        
        // Check for dangerous event handlers (but be smarter about it)
        const dangerousHandlers = document.querySelectorAll('[onclick], [onload], [onerror], [onmouseover]');
        
        // Filter out common legitimate uses
        const suspiciousHandlers = Array.from(dangerousHandlers).filter(el => {
          const handler = el.getAttribute('onclick') || el.getAttribute('onload') || 
                         el.getAttribute('onerror') || el.getAttribute('onmouseover');
          // Check if handler contains user input patterns
          return handler && (handler.includes('eval(') || handler.includes('document.write(') || 
                           handler.includes('innerHTML') || handler.length > 100);
        });
        
        if (suspiciousHandlers.length > 0) {
          this.addVulnerability({
            type: 'UNSAFE_EVENT_HANDLER',
            severity: 'medium',
            title: 'Potentially unsafe inline event handlers',
            description: `${suspiciousHandlers.length} inline event handler(s) with suspicious patterns`,
            recommendation: 'Use addEventListener with proper validation',
            evidence: `Found ${suspiciousHandlers.length} suspicious handler(s)`,
            confidence: 0.7
          });
        }
      } catch (error) {
        console.error('Content: Error in XSS check:', error);
      }
    }

    // Improved SQL Injection Detection with context awareness
    checkSQLInjectionImproved() {
      console.log('Content: Starting improved SQL injection analysis...');
      
      try {
        // 1. Check URL parameters with better patterns
        this.checkURLParametersForSQLImproved();
        
        // 2. Check forms for SQL injection risks
        this.checkFormsForSQL();
        
        // 3. Check for SQL error messages in page content
        this.checkSQLErrorMessages();
        
        // 4. Check JavaScript for SQL patterns with context
        this.checkJavaScriptForSQLImproved();
        
        // 5. Check for database references
        this.checkDatabaseReferences();
        
        console.log('Content: SQL injection analysis completed');
        
      } catch (error) {
        console.error('Content: Error in SQL injection check:', error);
      }
    }

    // Improved URL parameter SQL checking
    checkURLParametersForSQLImproved() {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        
        // More specific patterns that reduce false positives
        const sqlPatterns = [
          // High confidence patterns
          {
            pattern: /('\s*or\s+'1'\s*=\s*'1|"\s*or\s+"1"\s*=\s*"1)/i,
            confidence: 0.9,
            description: 'Classic SQL injection pattern'
          },
          {
            pattern: /(union\s+select\s+|union\s+all\s+select)/i,
            confidence: 0.85,
            description: 'UNION-based SQL injection'
          },
          {
            pattern: /(\s+and\s+\d+\s*=\s*\d+\s*(--|#))/i,
            confidence: 0.8,
            description: 'Boolean-based blind SQL injection'
          },
          {
            pattern: /(';|";)\s*(drop|delete|update|insert)\s+/i,
            confidence: 0.9,
            description: 'SQL command injection'
          },
          {
            pattern: /\bexec\s*\(\s*['"]?xp_/i,
            confidence: 0.95,
            description: 'SQL Server xp_cmdshell attempt'
          },
          {
            pattern: /\bwaitfor\s+delay\s+['"]?\d+:?\d+/i,
            confidence: 0.9,
            description: 'Time-based SQL injection'
          },
          {
            pattern: /benchmark\s*\(\s*\d+\s*,/i,
            confidence: 0.85,
            description: 'MySQL benchmark injection'
          }
        ];
        
        urlParams.forEach((value, key) => {
          // Skip if parameter name suggests it's not for database queries
          if (['page', 'tab', 'view', 'action', 'lang', 'theme'].includes(key.toLowerCase()) && 
              value.length < 20) {
            return;
          }
          
          // Check if value looks like UI text
          if (this.isUIText(value)) {
            return;
          }
          
          // Check patterns with confidence scoring
          sqlPatterns.forEach(({ pattern, confidence, description }) => {
            if (pattern.test(value)) {
              const finalConfidence = this.calculateConfidence('SQL_INJECTION', value, {
                validated: true,
                baseConfidence: confidence
              });
              
              if (SCANNER_CONFIG.DETECTION_MODE === 'balanced' && 
                  finalConfidence < SCANNER_CONFIG.MIN_CONFIDENCE) {
                return;
              }
              
              this.addVulnerability({
                type: 'SQL_INJECTION_URL_PARAMS',
                severity: finalConfidence > 0.8 ? 'critical' : 'high',
                title: 'SQL Injection Pattern Detected',
                description: `${description} in URL parameter "${key}"`,
                recommendation: 'Use parameterized queries and input validation',
                evidence: `Parameter: ${key}=${value.substring(0, 100)}`,
                payload: value,
                pattern: pattern.toString(),
                parameterName: key,
                confidence: finalConfidence
              });
            }
          });
        });
      } catch (error) {
        console.error('Content: Error checking URL parameters for SQL:', error);
      }
    }

    // Improved JavaScript SQL pattern detection
    checkJavaScriptForSQLImproved() {
      try {
        const scripts = document.querySelectorAll('script');
        let sqlInJS = false;
        let evidenceCount = 0;
        const sqlPatternEvidence = [];
        
        scripts.forEach(script => {
          const scriptContent = script.textContent || script.innerHTML || '';
          
          // Skip if it's minified library code (too many false positives)
          if (scriptContent.length > 50000 || scriptContent.includes('.min.js')) {
            return;
          }
          
          // More specific patterns that indicate actual SQL in JS
          const sqlPatterns = [
            {
              pattern: /["'`]\s*SELECT\s+.+\s+FROM\s+/i,
              description: 'SELECT query'
            },
            {
              pattern: /["'`]\s*INSERT\s+INTO\s+.+\s+VALUES\s*\(/i,
              description: 'INSERT query'
            },
            {
              pattern: /["'`]\s*UPDATE\s+.+\s+SET\s+/i,
              description: 'UPDATE query'
            },
            {
              pattern: /["'`]\s*DELETE\s+FROM\s+/i,
              description: 'DELETE query'
            },
            {
              pattern: /sql\s*=\s*["'`].*\s+\+\s+/i,
              description: 'Dynamic SQL construction'
            }
          ];
          
          sqlPatterns.forEach(({ pattern, description }) => {
            const matches = scriptContent.match(pattern);
            if (matches) {
              // Check if it's not a false positive (like documentation or comments)
              const match = matches[0];
              if (!this.isUIText(match)) {
                sqlInJS = true;
                evidenceCount++;
                sqlPatternEvidence.push({
                  pattern: match.substring(0, 100),
                  description: description,
                  scriptSrc: script.src || 'inline'
                });
              }
            }
          });
        });
        
        if (sqlInJS && evidenceCount > 0) {
          const confidence = this.calculateConfidence('SQL_IN_JS', null, {
            multipleInstances: evidenceCount > 1
          });
          
          if (SCANNER_CONFIG.DETECTION_MODE === 'balanced' && 
              confidence < SCANNER_CONFIG.MIN_CONFIDENCE) {
            return;
          }
          
          this.addVulnerability({
            type: 'SQL_IN_JAVASCRIPT',
            severity: 'high',
            title: 'SQL Queries in JavaScript Code',
            description: 'JavaScript code contains SQL query patterns which may indicate client-side SQL construction',
            recommendation: 'Move SQL queries to server-side code and use parameterized queries',
            evidence: `${evidenceCount} SQL pattern(s) found:\n${
              sqlPatternEvidence.slice(0, 3).map((e, i) => 
                `${i + 1}. ${e.description}: "${e.pattern}"`
              ).join('\n')
            }`,
            confidence: confidence
          });
        }
      } catch (error) {
        console.error('Content: Error checking JavaScript for SQL:', error);
      }
    }

    // Improved sensitive information detection with AWS patterns
    checkSensitiveInformationImproved() {
      try {
        console.log('Content: Scanning for sensitive information with improved patterns...');
        
        const pageText = document.body ? document.body.innerText : '';
        const pageHTML = document.body ? document.body.innerHTML : '';
        
        // Initialize Regional Compliance Detector (keeping existing)
        const userLocale = navigator.language || 'en-US';
        let regions = ['ALL'];
        
        const detector = new RegionalComplianceDetector(regions);
        const detections = detector.detectIdentifiers(pageText);
        const regionalVulnerabilities = detector.generateVulnerabilities();
        
        regionalVulnerabilities.forEach(vuln => {
          this.addVulnerability(vuln);
        });
        
        // Enhanced patterns including AWS
        const patterns = [
          {
            name: 'Credit card number',
            pattern: /\b(?:\d[ -]*?){13,19}\b/g,
            severity: 'critical',
            type: 'EXPOSED_CREDIT_CARD',
            validator: (match) => {
              const cleaned = match.replace(/\D/g, '');
              return cleaned.length >= 13 && cleaned.length <= 19 && this.luhnCheck(cleaned);
            }
          },
          // AWS patterns (your suggested patterns)
          {
            name: 'AWS access key ID',
            pattern: /\bA(?:K|S)IA[0-9A-Z]{16}\b/g,
            severity: 'high',
            type: 'AWS_KEY_ID_ONLY'
          },
          {
            name: 'AWS AKIA with Secret',
            pattern: /\bAKIA[0-9A-Z]{16}\b(?=[\s\S]{0,400}?(?:secret(?:_?access)?_?key|aws_secret_access_key|secretAccessKey|aws\.secretAccessKey|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?)/gs,
            severity: 'critical',
            type: 'EXPOSED_AWS_AKIA_BUNDLE'
          },
          {
            name: 'AWS ASIA with Secret and SessionToken',
            pattern: /\bASIA[0-9A-Z]{16}\b(?=[\s\S]{0,600}?(?:secret(?:_?access)?_?key|aws_secret_access_key|secretAccessKey|aws\.secretAccessKey|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?)(?=[\s\S]{0,600}?(?:aws_session_token|session[_-]?token|x-amz-security-token|sessionToken|AWS_SESSION_TOKEN)\s*[:=]\s*(['"][^'"]+['"]|[^\s]+))/gs,
            severity: 'critical',
            type: 'EXPOSED_AWS_ASIA_BUNDLE'
          },
          {
            name: 'Generic API key',
            pattern: /\b(api[_-]?key|apikey|api_token|access[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
            severity: 'high',
            type: 'EXPOSED_API_KEY'
          },
          {
            name: 'Private key',
            pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g,
            severity: 'critical',
            type: 'EXPOSED_PRIVATE_KEY'
          },
          {
            name: 'JWT token',
            pattern: /\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*\b/g,
            severity: 'high',
            type: 'EXPOSED_JWT'
          },
          {
            name: 'Basic auth credentials',
            pattern: /\b(https?:\/\/)([^:]+):([^@]+)@/g,
            severity: 'critical',
            type: 'EXPOSED_BASIC_AUTH'
          }
        ];
        
        patterns.forEach(({ name, pattern, severity, type, validator, maxAllowed }) => {
          const matches = pageText.match(pattern) || [];
          let validMatches = matches;
          
          if (validator) {
            validMatches = matches.filter(validator);
          }
          
          if (validMatches.length > (maxAllowed || 0)) {
            const confidence = this.calculateConfidence(type, validMatches[0], {
              validated: !!validator,
              multipleInstances: validMatches.length > 1
            });
            
            if (SCANNER_CONFIG.DETECTION_MODE === 'balanced' && 
                confidence < SCANNER_CONFIG.MIN_CONFIDENCE) {
              return;
            }
            
            this.addVulnerability({
              type: type,
              severity: severity,
              title: `${name} exposed in page content`,
              description: `Found ${validMatches.length} instance(s) of ${name.toLowerCase()} in page content`,
              recommendation: `Remove ${name.toLowerCase()} from client-side code and use server-side storage`,
              evidence: `Found ${validMatches.length} instance(s)`,
              confidence: confidence
            });
          }
        });
        
        // Check localStorage with better filtering
        this.checkStorageForSensitiveDataImproved();
        
      } catch (error) {
        console.error('Content: Error checking sensitive information:', error);
      }
    }

    // Improved storage checking with false positive reduction
    checkStorageForSensitiveDataImproved() {
      try {
        const sensitiveKeys = [
          'password', 'token', 'api_key', 'apikey', 'secret', 
          'private', 'card', 'cvv', 'ssn', 'cpf', 'aws_'
        ];
        
        // Check localStorage
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          const value = localStorage.getItem(key);
          
          // Skip common false positives
          if (FALSE_POSITIVE_PATTERNS.localStorage.some(fp => 
              key.toLowerCase().includes(fp))) {
            continue;
          }
          
          sensitiveKeys.forEach(sensitive => {
            if (key && key.toLowerCase().includes(sensitive)) {
              // Additional validation for tokens
              if (sensitive === 'token') {
                // Check if it looks like an actual token (not just a UI state token)
                if (!value || value.length < 20 || value === 'true' || value === 'false') {
                  return;
                }
              }
              
              const confidence = this.calculateConfidence('STORAGE', key, {
                validated: value && value.length > 10
              });
              
              if (SCANNER_CONFIG.DETECTION_MODE === 'balanced' && 
                  confidence < SCANNER_CONFIG.MIN_CONFIDENCE) {
                return;
              }
              
              this.addVulnerability({
                type: 'SENSITIVE_DATA_IN_STORAGE',
                severity: 'high',
                title: 'Sensitive data in localStorage',
                description: `Potentially sensitive data found in localStorage key: "${key}"`,
                recommendation: 'Never store sensitive data in client-side storage',
                evidence: `Key: ${key}`,
                confidence: confidence
              });
              return;
            }
          });
        }
        
      } catch (e) {
        // Storage not accessible
      }
    }

    // Luhn algorithm for credit card validation
    luhnCheck(num) {
      let sum = 0;
      let isEven = false;
      
      for (let i = num.length - 1; i >= 0; i--) {
        let digit = parseInt(num.charAt(i), 10);
        
        if (isEven) {
          digit *= 2;
          if (digit > 9) {
            digit -= 9;
          }
        }
        
        sum += digit;
        isEven = !isEven;
      }
      
      return (sum % 10) === 0;
    }

    // Process pre-analyzed headers from background script
    processHeaderAnalysis() {
      if (!this.headerAnalysis || this.headerAnalysis.length === 0) {
        console.log('Content: No header analysis received from background');
        return;
      }
      
      console.log(`Content: Processing ${this.headerAnalysis.length} header vulnerabilities`);
      
      // Add vulnerabilities found by background script
      this.headerAnalysis.forEach(vuln => {
        this.addVulnerability(vuln);
      });
      
      console.log(`Content: Added ${this.headerAnalysis.length} header-based vulnerabilities`);
      
      // Send updated results immediately
      this.sendResults();
    }

    // Keep existing check methods that don't need changes
    checkHTTPS() {
      try {
        if (window.location.protocol !== 'https:') {
          this.addVulnerability({
            type: 'NO_HTTPS',
            severity: 'critical',
            title: 'Site not using HTTPS',
            description: 'Data transmitted without encryption',
            recommendation: 'Implement HTTPS certificate and redirect all HTTP traffic to HTTPS',
            evidence: `Current protocol: ${window.location.protocol}`,
            confidence: 1.0
          });
        }
      } catch (error) {
        console.error('Content: Error in HTTPS check:', error);
      }
    }
    
    checkInsecureForms() {
      try {
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
          if (window.location.protocol === 'https:' && 
              form.action && form.action.startsWith('http://')) {
            this.addVulnerability({
              type: 'INSECURE_FORM',
              severity: 'high',
              title: 'Form sends data via HTTP',
              description: 'Form data will be sent without encryption',
              recommendation: 'Use HTTPS in form action',
              evidence: `Form action: ${form.action}`,
              confidence: 1.0
            });
          }
          
          const passwordFields = form.querySelectorAll('input[type="password"]');
          if (passwordFields.length > 0 && window.location.protocol !== 'https:') {
            this.addVulnerability({
              type: 'PASSWORD_OVER_HTTP',
              severity: 'critical',
              title: 'Password field on HTTP page',
              description: 'Passwords will be transmitted without encryption!',
              recommendation: 'NEVER collect passwords without HTTPS',
              evidence: `${passwordFields.length} password field(s) found`,
              confidence: 1.0
            });
            return;
          }
        });
      } catch (error) {
        console.error('Content: Error in forms check:', error);
      }
    }
    
    checkMixedContent() {
      try {
        if (window.location.protocol === 'https:') {
          const httpScripts = document.querySelectorAll('script[src^="http://"]');
          if (httpScripts.length > 0) {
            this.addVulnerability({
              type: 'MIXED_CONTENT_SCRIPTS',
              severity: 'critical',
              title: 'Scripts loaded via HTTP',
              description: 'Scripts can be intercepted and modified',
              recommendation: 'Load all scripts via HTTPS',
              evidence: `${httpScripts.length} insecure script(s)`,
              confidence: 1.0
            });
          }
          
          // Downgrade images to info level (not really a security issue)
          const httpImages = document.querySelectorAll('img[src^="http://"]');
          if (httpImages.length > 5) { // Only report if many images
            this.addVulnerability({
              type: 'MIXED_CONTENT_IMAGES',
              severity: 'info',
              title: 'Images loaded via HTTP',
              description: 'Some images are loaded without encryption',
              recommendation: 'Consider loading images via HTTPS',
              evidence: `${httpImages.length} insecure image(s)`,
              confidence: 0.5
            });
          }
        }
      } catch (error) {
        console.error('Content: Error in mixed content check:', error);
      }
    }

    // [Keep all other existing check methods that don't need changes]
    // checkOutdatedLibraries, checkCSP, checkExternalLinks, checkBasicAuth,
    // checkFormsForSQL, checkSQLErrorMessages, checkDatabaseReferences,
    // checkCookieSecurity, checkAPIsAndCORS, checkSubresourceIntegrity,
    // checkCommentsForSensitiveInfo, checkWebSocketSecurity, checkIframeSecurity,
    // checkAdvancedFormSecurity, checkMetaTagsSecurity
    // [These remain the same as in original code]
    
    // Enhanced addVulnerability with deduplication
    addVulnerability(vuln) {
      try {
        // Add confidence if not present
        if (!vuln.confidence && vuln.confidence !== 0) {
          vuln.confidence = this.calculateConfidence(vuln.type, vuln.evidence);
        }
        
        // In balanced mode, filter low confidence
        if (SCANNER_CONFIG.DETECTION_MODE === 'balanced' && 
            vuln.confidence < SCANNER_CONFIG.MIN_CONFIDENCE && 
            vuln.severity !== 'critical') {
          console.log(`Filtered low confidence vulnerability: ${vuln.title} (${vuln.confidence})`);
          return;
        }
        
        // Enhanced vulnerability object
        const enhancedVuln = {
          ...vuln,
          timestamp: Date.now(),
          url: window.location.href
        };
        
        // Normalize severity
        enhancedVuln.severity = (vuln.severity || 'info').toLowerCase();
        
        // Smart deduplication - group similar vulnerabilities
        const isDuplicate = this.vulnerabilities.some(existing => {
          // Exact match
          if (existing.type === enhancedVuln.type && 
              existing.title === enhancedVuln.title &&
              existing.evidence === enhancedVuln.evidence) {
            return true;
          }
          
          // Group similar SQL injection findings
          if (existing.type === enhancedVuln.type && 
              existing.type.includes('SQL_INJECTION') &&
              existing.parameterName === enhancedVuln.parameterName) {
            return true;
          }
          
          return false;
        });
        
        if (!isDuplicate) {
          this.vulnerabilities.push(enhancedVuln);
          console.log(`🚨 Vulnerability detected: ${enhancedVuln.title} [${enhancedVuln.severity}] (confidence: ${enhancedVuln.confidence?.toFixed(2)})`);
        }
      } catch (error) {
        console.error('Content: Error adding vulnerability:', error);
      }
    }
    
    sendResults() {
      try {
        // Group similar vulnerabilities
        const groupedVulnerabilities = this.groupSimilarVulnerabilities(this.vulnerabilities);
        
        const score = this.calculateSecurityScore(groupedVulnerabilities);
        
        const results = {
          type: 'SCAN_COMPLETE',
          url: window.location.href,
          vulnerabilities: groupedVulnerabilities,
          score: score,
          timestamp: Date.now()
        };
        
        console.log(`Content: Sending ${groupedVulnerabilities.length} vulnerabilities with score ${score}`);
        
        // Send to background script with multiple attempts
        let attempts = 0;
        const maxAttempts = 3;
        
        const trySend = () => {
          attempts++;
          console.log(`Content: Send attempt ${attempts}`);
          
          chrome.runtime.sendMessage(results, (response) => {
            if (chrome.runtime.lastError) {
              console.error(`Content: Send attempt ${attempts} failed:`, chrome.runtime.lastError);
              if (attempts < maxAttempts) {
                setTimeout(trySend, 500 * attempts);
              }
            } else {
              console.log(`Content: ✅ Results sent successfully on attempt ${attempts}`);
            }
          });
        };
        
        trySend();
        
      } catch (error) {
        console.error('Content: Exception in sendResults:', error);
      }
    }
    
    // Group similar vulnerabilities to reduce noise
    groupSimilarVulnerabilities(vulnerabilities) {
      const grouped = new Map();
      
      vulnerabilities.forEach(vuln => {
        const key = `${vuln.type}-${vuln.severity}`;
        
        if (!grouped.has(key)) {
          grouped.set(key, {
            ...vuln,
            count: 1,
            instances: [vuln]
          });
        } else {
          const group = grouped.get(key);
          group.count++;
          group.instances.push(vuln);
          
          // Update title to show count
          if (group.count === 2) {
            group.title = `${group.title} (${group.count} instances)`;
          } else if (group.count > 2) {
            group.title = group.title.replace(/\(\d+ instances\)/, `(${group.count} instances)`);
          }
          
          // Combine evidence
          if (!group.evidence.includes('instance(s)')) {
            group.evidence = `${group.count} instance(s) found`;
          }
        }
      });
      
      return Array.from(grouped.values());
    }
    
    calculateSecurityScore(vulnerabilities = null) {
      const vulnList = vulnerabilities || this.vulnerabilities;
      let score = 100;
      
      const penalties = {
        critical: 25,
        high: 15,
        medium: 10,
        low: 5,
        info: 0
      };
      
      vulnList.forEach(vuln => {
        const severity = (vuln.severity || 'info').toLowerCase();
        if (severity !== 'info') {
          // Apply penalty considering confidence
          const confidence = vuln.confidence || 1;
          const penalty = penalties[severity] || 5;
          score -= penalty * confidence;
        }
      });
      
      return Math.max(0, Math.round(score));
    }
  }
  
  // Force start the scanner
  console.log('Content: Creating scanner instance...');
  try {
    const scanner = new VulnerabilityScanner();
    window.navSecScanner = scanner; // For debugging
    console.log('Content: ✅ Scanner v1.3 created and started with false positive reduction');
  } catch (error) {
    console.error('Content: ❌ Failed to create scanner:', error);
  }
  
})();
