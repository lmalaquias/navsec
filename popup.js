// popup.js - Enhanced Scanner Interface with Bug Fixes
// Author: Leandro Malaquias
// Extension: NavSec Vulnerability Scanner v1.1
document.addEventListener('DOMContentLoaded', async () => {
  console.log('NavSec Popup v1.1: Loading...');
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    console.log('Popup: Current tab ID:', tab.id);
    
    // Simplified result loading with timeout
    let resultsReceived = false;
    let loadingTimeout;
    
    // Show loading immediately
    showLoading();
    
    // Set timeout for loading state
    loadingTimeout = setTimeout(() => {
      if (!resultsReceived) {
        console.log('Popup: Loading timeout, showing no scan message');
        displayNoScan();
      }
    }, 5000);
    
    // Method 1: Direct message method (primary)
    chrome.runtime.sendMessage({ 
      type: 'GET_RESULTS_DIRECT', 
      tabId: tab.id 
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.log('Popup: Direct method failed:', chrome.runtime.lastError.message);
        return;
      }
      
      if (response && response.type === 'SCAN_RESULTS' && !resultsReceived) {
        resultsReceived = true;
        clearTimeout(loadingTimeout);
        
        if (response.data) {
          console.log('Popup: Displaying results via direct method:', response.data);
          displayResults(response.data);
        } else {
          console.log('Popup: No data via direct method');
          displayNoScan();
        }
      }
    });
    
    // Method 2: Port connection (fallback)
    setTimeout(() => {
      if (!resultsReceived) {
        try {
          const port = chrome.runtime.connect({ name: 'popup' });
          
          port.postMessage({ type: 'GET_RESULTS', tabId: tab.id });
          
          port.onMessage.addListener((msg) => {
            if (msg.type === 'SCAN_RESULTS' && !resultsReceived) {
              resultsReceived = true;
              clearTimeout(loadingTimeout);
              
              if (msg.data) {
                console.log('Popup: Displaying results via port:', msg.data);
                displayResults(msg.data);
              } else {
                displayNoScan();
              }
            }
          });
          
          port.onDisconnect.addListener(() => {
            console.log('Popup: Port disconnected');
          });
          
        } catch (error) {
          console.log('Popup: Port connection failed:', error);
        }
      }
    }, 1000);
    
  } catch (error) {
    console.error('Popup: Initialization failed:', error);
    displayError('Failed to initialize scanner interface');
  }
});

function showLoading() {
  document.getElementById('content').innerHTML = `
    <div class="loading">
      <div class="spinner"></div>
      <p>Initializing Security Analysis</p>
      <p>Checking for scan results...</p>
    </div>
  `;
}

function displayResults(results) {
  try {
    // Debug logging
    console.log('Popup: Raw results:', results);
    console.log('Popup: Vulnerabilities:', results.vulnerabilities);
    
    const scoreColor = getScoreColor(results.score);
    
    // Calculate severity counts with normalization
    const summary = getSummary(results.vulnerabilities);
    console.log('Popup: Vulnerability summary:', summary);
    
    let html = `
      <div class="score-container">
        <div class="score-display">
          <div class="score-text" style="color: ${scoreColor};">${results.score}</div>
          <div class="score-label">Security Score</div>
          <div class="score-description">${getScoreDescription(results.score)}</div>
        </div>
        
        <!-- Score comparison chart -->
        <div class="score-chart">
          <div class="chart-title">Score Comparison</div>
          <div class="chart-bar-container">
            <!-- Score ranges -->
            <div style="position: absolute; height: 100%; width: 20%; left: 0; background: #e74c3c;"></div>
            <div style="position: absolute; height: 100%; width: 20%; left: 20%; background: #e67e22;"></div>
            <div style="position: absolute; height: 100%; width: 20%; left: 40%; background: #f39c12;"></div>
            <div style="position: absolute; height: 100%; width: 20%; left: 60%; background: #2ecc71;"></div>
            <div style="position: absolute; height: 100%; width: 20%; left: 80%; background: #27ae60;"></div>
            
            <!-- Current score indicator -->
            <div style="position: absolute; top: -5px; left: ${results.score}%; transform: translateX(-50%); width: 0; height: 0; border-left: 8px solid transparent; border-right: 8px solid transparent; border-top: 10px solid #2c3e50;"></div>
            <div style="position: absolute; top: -25px; left: ${results.score}%; transform: translateX(-50%); background: #2c3e50; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">${results.score}</div>
          </div>
          <div style="display: flex; justify-content: space-between; margin-top: 8px; font-size: 10px; color: #95a5a6;">
            <span>0</span>
            <span>20</span>
            <span>40</span>
            <span>60</span>
            <span>80</span>
            <span>100</span>
          </div>
          <div style="display: flex; justify-content: space-between; margin-top: 5px; font-size: 11px;">
            <span style="color: #e74c3c;">Critical</span>
            <span style="color: #e67e22;">Poor</span>
            <span style="color: #f39c12;">Fair</span>
            <span style="color: #2ecc71;">Good</span>
            <span style="color: #27ae60;">Excellent</span>
          </div>
        </div>
      </div>
    `;
    
    if (results.vulnerabilities && results.vulnerabilities.length > 0) {
      // Enhanced summary with category breakdown
      const categories = getCategoryBreakdown(results.vulnerabilities);
      
      html += `
        <div class="summary">
          <div class="summary-title">Assessment Summary</div>
          <div class="summary-row">
            <span>Total vulnerabilities:</span>
            <strong>${results.vulnerabilities.length}</strong>
          </div>
          ${summary.critical > 0 ? `
            <div class="summary-row">
              <span>Critical:</span>
              <strong style="color: #e74c3c">${summary.critical}</strong>
            </div>
          ` : ''}
          ${summary.high > 0 ? `
            <div class="summary-row">
              <span>High:</span>
              <strong style="color: #e67e22">${summary.high}</strong>
            </div>
          ` : ''}
          ${summary.medium > 0 ? `
            <div class="summary-row">
              <span>Medium:</span>
              <strong style="color: #f39c12">${summary.medium}</strong>
            </div>
          ` : ''}
          ${summary.low > 0 ? `
            <div class="summary-row">
              <span>Low:</span>
              <strong style="color: #3498db">${summary.low}</strong>
            </div>
          ` : ''}
          ${summary.info > 0 ? `
            <div class="summary-row">
              <span>Info:</span>
              <strong style="color: #2ecc71">${summary.info}</strong>
            </div>
          ` : ''}
        </div>
      `;
      
      // Add category indicators if we have multiple types
      if (Object.keys(categories).length > 1) {
        html += `
          <div class="summary">
            <div class="summary-title">Categories Found</div>
            ${Object.entries(categories).map(([category, count]) => `
              <div class="summary-row">
                <span>${getCategoryIcon(category)} ${category}:</span>
                <strong>${count}</strong>
              </div>
            `).join('')}
          </div>
        `;
      }
      
      // Vulnerabilities list
      html += '<div class="vulnerabilities-list">';
      html += '<div class="section-title">Security Findings</div>';
      
      // Sort by severity and then by category
      const ordered = results.vulnerabilities.sort((a, b) => {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const aSeverity = (a.severity || 'info').toLowerCase();
        const bSeverity = (b.severity || 'info').toLowerCase();
        const severityDiff = severityOrder[aSeverity] - severityOrder[bSeverity];
        if (severityDiff !== 0) return severityDiff;
        
        // Secondary sort by category for better organization
        const categoryA = getVulnerabilityCategory(a.type);
        const categoryB = getVulnerabilityCategory(b.type);
        return categoryA.localeCompare(categoryB);
      });
      
      ordered.forEach((vuln, index) => {
        const category = getVulnerabilityCategory(vuln.type);
        const categoryIcon = getCategoryIcon(category);
        const severity = (vuln.severity || 'info').toLowerCase();
        
        html += `
          <div class="vulnerability-item ${severity}">
            <div class="vuln-header">
              <span class="vuln-title">${categoryIcon} ${vuln.title}</span>
              <span class="vuln-severity severity-${severity}">${severity}</span>
            </div>
            <div class="vuln-description">${vuln.description}</div>
            <div class="vuln-recommendation">💡 ${vuln.recommendation}</div>
            ${vuln.evidence ? `
              <div class="vuln-evidence">
                <div class="evidence-label">Technical Evidence</div>
                <div class="evidence-content">${vuln.evidence}</div>
              </div>
            ` : ''}
          </div>
        `;
      });
      
      html += '</div>';
    } else {
      html += `
        <div class="no-vulnerabilities">
          <svg viewBox="0 0 24 24" fill="#2ecc71" width="48" height="48">
            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/>
          </svg>
          <h3>Secure Site!</h3>
          <p>No vulnerabilities detected during this security assessment.</p>
          <p>
            ✓ Headers & CSP checked<br>
            ✓ Transport security verified<br>
            ✓ Content analysis completed<br>
            ✓ Configuration validated
          </p>
        </div>
      `;
    }
    
    // Action buttons
    html += `
      <div class="actions">
        <button class="btn btn-primary" id="scanAgainBtn">
          🔄 Rescan
        </button>
        <button class="btn btn-secondary" id="exportReportBtn">
          📄 Export
        </button>
      </div>
    `;
    
    document.getElementById('content').innerHTML = html;
    
    // Add event listeners after content is inserted
    setupEventListeners();
    
  } catch (error) {
    console.error('Popup: Error displaying results:', error);
    displayError('Failed to display scan results');
  }
}

function displayNoScan() {
  document.getElementById('content').innerHTML = `
    <div class="no-vulnerabilities">
      <div style="font-size: 48px; margin-bottom: 20px;">🔍</div>
      <h3 style="color: #2c3e50;">No Scan Results</h3>
      <p>
        No security analysis found for this page.<br>
        The scanner may still be analyzing or the page might not be supported.
      </p>
      <button class="btn btn-primary" id="startScanBtn" style="margin-top: 20px;">
        🔄 Start Analysis
      </button>
      <p style="margin-top: 20px;">
        Passive analysis includes:<br>
        Headers, CSP, Transport Security, Content Check
      </p>
    </div>
  `;
  
  // Add event listener
  setupEventListeners();
}

function displayError(message) {
  document.getElementById('content').innerHTML = `
    <div class="error-container">
      <div class="error-icon">⚠️</div>
      <h3>Error</h3>
      <p>${message}</p>
      <button class="btn btn-primary" id="retryBtn">
        🔄 Retry
      </button>
    </div>
  `;
  
  // Add event listener
  setupEventListeners();
}

// Helper functions for enhanced categorization
function getVulnerabilityCategory(type) {
  const categories = {
    // Transport Security
    'NO_HTTPS': 'Transport Security',
    'INSECURE_FORM': 'Transport Security',
    'PASSWORD_OVER_HTTP': 'Transport Security',
    'MIXED_CONTENT_SCRIPTS': 'Transport Security',
    'MIXED_CONTENT_IMAGES': 'Transport Security',
    'MIXED_CONTENT_IFRAMES': 'Transport Security',
    'COOKIES_NOT_SECURE': 'Transport Security',
    'HTTPS_VERIFIED': 'Transport Security',
    'INSECURE_WEBSOCKET': 'Transport Security',
    'WEBSOCKET_DETECTED': 'Transport Security',
    
    // Headers & CSP
    'MISSING_X_FRAME_OPTIONS': 'Headers & CSP',
    'MISSING_HSTS': 'Headers & CSP',
    'MISSING_CONTENT_TYPE_OPTIONS': 'Headers & CSP',
    'CSP_UNSAFE_INLINE': 'Headers & CSP',
    'CSP_UNSAFE_EVAL': 'Headers & CSP',
    'CSP_WILDCARD': 'Headers & CSP',
    'NO_CSP': 'Headers & CSP',
    'MISSING_REFERRER_POLICY': 'Headers & CSP',
    'MISSING_SRI_SCRIPTS': 'Headers & CSP',
    'MISSING_SRI_STYLES': 'Headers & CSP',
    
    // XSS & Injection
    'XSS_VULNERABILITY': 'XSS & Injection',
    'REFLECTED_XSS_PARAM': 'XSS & Injection',
    'UNSAFE_EVENT_HANDLER': 'XSS & Injection',
    
    // SQL Injection
    'SQL_INJECTION_URL_PARAMS': 'SQL Injection',
    'SQL_INJECTION_FORM_HIGH_RISK': 'SQL Injection',
    'SQL_INJECTION_FORM_MEDIUM_RISK': 'SQL Injection',
    'SQL_INJECTION_FORM_LOW_RISK': 'SQL Injection',
    'SQL_ERROR_MESSAGES': 'SQL Injection',
    'SQL_IN_JAVASCRIPT': 'SQL Injection',
    'SQL_INJECTION_DYNAMIC_EXECUTION': 'SQL Injection',
    'DATABASE_CONNECTION_EXPOSED': 'SQL Injection',
    'DATABASE_REFERENCES_DETECTED': 'SQL Injection',
    'DATABASE_SCHEMA_EXPOSED': 'SQL Injection',
    
    // Authentication & Session
    'JWT_IN_LOCALSTORAGE': 'Authentication',
    'MISSING_CSRF_PROTECTION': 'Authentication',
    'WEAK_SESSION_ID': 'Authentication',
    'NO_CAPTCHA': 'Authentication',
    'COOKIES_NOT_HTTPONLY': 'Authentication',
    'COOKIES_SECURE_FLAG_CHECK': 'Authentication',
    
    // Privacy & Data
    'EXPOSED_CPF': 'Privacy & Data',
    'EXPOSED_CNPJ': 'Privacy & Data',
    'EXPOSED_SSN': 'Privacy & Data',
    'EXPOSED_EIN': 'Privacy & Data',
    'EXPOSED_CREDIT_CARD': 'Privacy & Data',
    'EXPOSED_API_KEY': 'Privacy & Data',
    'EXPOSED_PRIVATE_KEY': 'Privacy & Data',
    'EXPOSED_AWS_KEY': 'Privacy & Data',
    'EXPOSED_EMAIL': 'Privacy & Data',
    'EXPOSED_JWT': 'Privacy & Data',
    'EXPOSED_BASIC_AUTH': 'Privacy & Data',
    'SENSITIVE_DATA_IN_STORAGE': 'Privacy & Data',
    'MULTI_REGION_COMPLIANCE_RISK': 'Privacy & Data',
    
    // Forms & Input
    'CREDIT_CARD_FORM': 'Forms & Input',
    'UNRESTRICTED_FILE_UPLOAD': 'Forms & Input',
    'NO_PASSWORD_STRENGTH': 'Forms & Input',
    'AUTOCOMPLETE_SENSITIVE': 'Forms & Input',
    
    // Comments & Metadata
    'COMMENT_TODO_WITH_PASSWORD': 'Comments & Metadata',
    'COMMENT_TODO_WITH_API': 'Comments & Metadata',
    'COMMENT_FIXME_SECURITY': 'Comments & Metadata',
    'COMMENT_HACK_COMMENT': 'Comments & Metadata',
    'COMMENT_DEV_URL_IN_COMMENT': 'Comments & Metadata',
    'COMMENT_CREDS_IN_COMMENT': 'Comments & Metadata',
    'COMMENT_LOCALHOST_IN_COMMENT': 'Comments & Metadata',
    'COMMENT_IP_IN_COMMENT': 'Comments & Metadata',
    'NOINDEX_META': 'Comments & Metadata',
    'GENERATOR_META_EXPOSED': 'Comments & Metadata',
    'INTERNAL_URL_IN_OG': 'Comments & Metadata',
    'AUTHOR_EMAIL_EXPOSED': 'Comments & Metadata',
    
    // Iframe & External
    'IFRAME_NO_SANDBOX': 'Iframe & External',
    'EXTERNAL_IFRAMES': 'Iframe & External',
    'INSECURE_IFRAME': 'Iframe & External',
    'EXTERNAL_RESOURCES': 'Iframe & External',
    
    // General Security
    'OUTDATED_JQUERY': 'General Security',
    'OUTDATED_ANGULAR': 'General Security',
    'TABNABBING': 'General Security',
    'COOKIES_NOT_HTTPONLY': 'General Security'
  };
  
  // Handle types that start with EXPOSED_ for regional compliance
  if (type.startsWith('EXPOSED_') && !categories[type]) {
    return 'Privacy & Data';
  }
  
  return categories[type] || 'General Security';
}

function getCategoryIcon(category) {
  const icons = {
    'Transport Security': '🔒',
    'Headers & CSP': '🛡️',
    'XSS & Injection': '⚡',
    'SQL Injection': '💉',
    'Authentication': '🔐',
    'Privacy & Data': '🔑',
    'Forms & Input': '📝',
    'Comments & Metadata': '💬',
    'Iframe & External': '🖼️',
    'General Security': '🔧'
  };
  
  return icons[category] || '🔧';
}

function getCategoryBreakdown(vulnerabilities) {
  return vulnerabilities.reduce((acc, vuln) => {
    const category = getVulnerabilityCategory(vuln.type);
    acc[category] = (acc[category] || 0) + 1;
    return acc;
  }, {});
}

function getScoreColor(score) {
  if (score >= 90) return '#27ae60';
  if (score >= 70) return '#2ecc71';
  if (score >= 50) return '#f39c12';
  if (score >= 30) return '#e67e22';
  return '#e74c3c';
}

function getScoreDescription(score) {
  if (score >= 90) return 'Excellent Security Posture';
  if (score >= 70) return 'Good Security Posture';
  if (score >= 50) return 'Fair Security Posture';
  if (score >= 30) return 'Poor Security Posture';
  return 'Critical Security Issues';
}

function getSummary(vulnerabilities) {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  vulnerabilities.forEach(vuln => {
    const severity = (vuln.severity || 'info').toLowerCase();
    if (summary.hasOwnProperty(severity)) {
      summary[severity]++;
    } else {
      console.warn('Unknown severity:', severity, 'for vulnerability:', vuln.type);
      summary.info++;
    }
  });
  
  return summary;
}

// Setup event listeners for buttons (CSP compliant)
function setupEventListeners() {
  // Scan Again button
  const scanAgainBtn = document.getElementById('scanAgainBtn');
  if (scanAgainBtn) {
    scanAgainBtn.addEventListener('click', simpleReload);
  }
  
  // Export Report button
  const exportReportBtn = document.getElementById('exportReportBtn');
  if (exportReportBtn) {
    exportReportBtn.addEventListener('click', exportReport);
  }
  
  // Start Scan button
  const startScanBtn = document.getElementById('startScanBtn');
  if (startScanBtn) {
    startScanBtn.addEventListener('click', startScan);
  }
  
  // Retry button
  const retryBtn = document.getElementById('retryBtn');
  if (retryBtn) {
    retryBtn.addEventListener('click', () => window.location.reload());
  }
}

// Action functions
async function simpleReload() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    console.log('Popup: Simple reload requested for tab:', tab.id);
    
    // Show immediate feedback
    showLoading();
    
    // Reload the tab
    await chrome.tabs.reload(tab.id);
    
    // Close popup after reload
    setTimeout(() => {
      window.close();
    }, 500);
    
  } catch (error) {
    console.error('Simple reload failed:', error);
    displayError('Failed to reload page');
  }
}

async function startScan() {
  console.log('Popup: Start scan requested');
  await simpleReload();
}

async function exportReport() {
  console.log('Popup: Export report requested');
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    console.log('Popup: Exporting report for tab:', tab.id);
    
    // Get export button and show loading state
    const exportBtn = document.getElementById('exportReportBtn');
    if (!exportBtn) {
      console.error('Export button not found');
      return;
    }
    
    const originalText = exportBtn.innerHTML;
    const originalDisabled = exportBtn.disabled;
    
    exportBtn.innerHTML = '⏳ Generating...';
    exportBtn.disabled = true;
    
    // Send export request with Promise wrapper for better error handling
    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ 
        type: 'EXPORT_REPORT', 
        tabId: tab.id 
      }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response);
        }
      });
      
      // Timeout after 15 seconds
      setTimeout(() => {
        reject(new Error('Export request timed out'));
      }, 15000);
    });
    
    console.log('Export response:', response);
    
    if (response && response.success) {
      console.log('Export successful');
      exportBtn.innerHTML = '✅ Downloaded!';
      
      // Show success message briefly
      setTimeout(() => {
        exportBtn.innerHTML = originalText;
        exportBtn.disabled = originalDisabled;
      }, 3000);
      
    } else {
      // Handle specific error from background
      const errorMessage = response?.error || 'Unknown error occurred';
      console.error('Export failed with error:', errorMessage);
      
      exportBtn.innerHTML = '❌ Failed';
      exportBtn.title = `Error: ${errorMessage}`;
      
      // Show detailed error in console for debugging
      console.error('Detailed export error:', {
        response,
        tabId: tab.id,
        error: errorMessage
      });
      
      // Restore button after delay
      setTimeout(() => {
        exportBtn.innerHTML = originalText;
        exportBtn.disabled = originalDisabled;
        exportBtn.title = '';
      }, 4000);
    }
    
  } catch (error) {
    console.error('Export setup failed:', error);
    
    // Handle different types of errors
    const exportBtn = document.getElementById('exportReportBtn');
    if (exportBtn) {
      if (error.message.includes('timed out')) {
        exportBtn.innerHTML = '⏱️ Timeout';
        exportBtn.title = 'Export timed out - try again';
      } else if (error.message.includes('No scan results')) {
        exportBtn.innerHTML = '📋 No Data';
        exportBtn.title = 'No scan results found - run a scan first';
      } else {
        exportBtn.innerHTML = '❌ Error';
        exportBtn.title = `Error: ${error.message}`;
      }
      
      exportBtn.disabled = true;
      
      // Restore button after delay
      setTimeout(() => {
        exportBtn.innerHTML = '📄 Export';
        exportBtn.disabled = false;
        exportBtn.title = '';
      }, 4000);
    }
  }
}