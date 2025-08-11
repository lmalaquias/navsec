// background.js - Service Worker for NavSec Vulnerability Scanner v1.1
// Author: Leandro Malaquias
// NO DOM REFERENCES - Service Worker Compatible Only

console.log('🛡️ NavSec Background Service Worker started v1.1');

// Configuration
const NAVSEC_CONFIG = {
  VERSION: '1.1',
  FEATURES: {
    USE_STORAGE: true,
    ENHANCED_VALIDATION: true,
    SMART_SPA_DETECTION: true,
    REDUCE_FALSE_POSITIVES: true
  },
  STORAGE: {
    MAX_AGE_DAYS: 7,
    MAX_RESULTS: 100
  }
};

// Store scan results in memory
const scanResults = new Map();

// Initialize on install
chrome.runtime.onInstalled.addListener(() => {
  console.log('NavSec: Extension installed/updated to v1.1');
  cleanOldStorageData();
});

// Clean old storage data
async function cleanOldStorageData() {
  try {
    const allData = await chrome.storage.local.get(null);
    const now = Date.now();
    const maxAge = NAVSEC_CONFIG.STORAGE.MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
    
    const keysToRemove = [];
    for (const [key, value] of Object.entries(allData)) {
      if (key.startsWith('scan_') && value.timestamp) {
        if (now - value.timestamp > maxAge) {
          keysToRemove.push(key);
        }
      }
    }
    
    if (keysToRemove.length > 0) {
      await chrome.storage.local.remove(keysToRemove);
      console.log(`NavSec: Cleaned ${keysToRemove.length} old scan results`);
    }
  } catch (error) {
    console.error('NavSec: Error cleaning storage:', error);
  }
}

// Save results to both memory and storage
async function saveScanResults(tabId, results) {
  scanResults.set(tabId, results);
  
  if (NAVSEC_CONFIG.FEATURES.USE_STORAGE) {
    try {
      await chrome.storage.local.set({ [`scan_${tabId}`]: results });
    } catch (error) {
      console.error('NavSec: Error saving to storage:', error);
    }
  }
}

// Get results from memory or storage
async function getScanResults(tabId) {
  let results = scanResults.get(tabId);
  
  if (!results && NAVSEC_CONFIG.FEATURES.USE_STORAGE) {
    try {
      const data = await chrome.storage.local.get(`scan_${tabId}`);
      results = data[`scan_${tabId}`];
      
      if (results) {
        scanResults.set(tabId, results);
      }
    } catch (error) {
      console.error('NavSec: Error reading from storage:', error);
    }
  }
  
  return results;
}

// Enhanced export report functionality
async function exportReport(tabId) {
  console.log('Background: Starting export for tab:', tabId);
  
  try {
    if (!tabId || typeof tabId !== 'number') {
      throw new Error('Invalid tab ID provided');
    }
    
    const results = await getScanResults(tabId);
    if (!results) {
      throw new Error('No scan results found for this tab. Please run a scan first.');
    }
    
    console.log('Background: Found results for export:', {
      url: results.url,
      score: results.score,
      vulnCount: results.vulnerabilities ? results.vulnerabilities.length : 0
    });
    
    if (!results.url) {
      throw new Error('Invalid scan results: missing URL');
    }
    
    if (!Array.isArray(results.vulnerabilities)) {
      results.vulnerabilities = [];
    }
    
    const report = generateCompactHTMLReport(results);
    
    if (!report || report.length < 50) {
      throw new Error('Generated report is empty or too short');
    }
    
    console.log('Background: Report generated successfully, size:', report.length);
    
    const timestamp = new Date().toISOString().split('T')[0];
    let domain;
    try {
      domain = new URL(results.url).hostname.replace(/[^a-zA-Z0-9]/g, '-');
    } catch (e) {
      domain = 'unknown-site';
    }
    
    const filename = `navsec-report-${domain}-${timestamp}.html`;
    
    // Method 1: Try direct data URL download
    try {
      const dataUrl = 'data:text/html;charset=utf-8,' + encodeURIComponent(report);
      
      console.log('Background: Attempting data URL download...');
      
      const downloadId = await new Promise((resolve, reject) => {
        chrome.downloads.download({
          url: dataUrl,
          filename: filename,
          saveAs: false,
          conflictAction: 'uniquify'
        }, (downloadId) => {
          if (chrome.runtime.lastError) {
            console.error('Background: Data URL download failed:', chrome.runtime.lastError);
            reject(new Error(chrome.runtime.lastError.message));
          } else if (downloadId) {
            console.log('Background: Data URL download successful, ID:', downloadId);
            resolve(downloadId);
          } else {
            reject(new Error('No download ID returned'));
          }
        });
      });
      
      return { success: true, downloadId, method: 'dataUrl' };
      
    } catch (dataUrlError) {
      console.log('Background: Data URL method failed, trying content script injection...');
      
      // Method 2: Content script injection
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        const downloadResult = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: function(reportContent, filename) {
            try {
              const blob = new Blob([reportContent], { type: 'text/html' });
              const url = URL.createObjectURL(blob);
              
              const link = document.createElement('a');
              link.href = url;
              link.download = filename;
              link.style.display = 'none';
              
              document.body.appendChild(link);
              link.click();
              document.body.removeChild(link);
              
              URL.revokeObjectURL(url);
              
              return { success: true };
            } catch (error) {
              return { success: false, error: error.message };
            }
          },
          args: [report, filename]
        });
        
        if (downloadResult && downloadResult[0] && downloadResult[0].result && downloadResult[0].result.success) {
          console.log('Background: Content script injection successful');
          return { success: true, downloadId: 'content-script', method: 'injection' };
        } else {
          throw new Error('Content script injection failed');
        }
        
      } catch (injectionError) {
        console.error('Background: Content script injection failed:', injectionError);
        
        // Method 3: Storage fallback
        try {
          console.log('Background: Using storage fallback method...');
          
          await chrome.storage.local.set({
            [`export_${tabId}_${Date.now()}`]: {
              filename: filename,
              content: report,
              timestamp: Date.now()
            }
          });
          
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon128.png',
            title: 'NavSec Export Ready',
            message: 'Report saved to extension storage. Click extension icon to access.',
            priority: 2
          });
          
          return { 
            success: true, 
            downloadId: 'storage-fallback', 
            method: 'storage',
            message: 'Report saved to extension storage'
          };
          
        } catch (storageError) {
          console.error('Background: All export methods failed');
          throw new Error(`All export methods failed. Last error: ${storageError.message}`);
        }
      }
    }
    
  } catch (error) {
    console.error('Background: Export failed completely:', error);
    throw error;
  }
}

// Generate compact HTML report
function generateCompactHTMLReport(results) {
  try {
    console.log('Background: Generating compact HTML report...');
    
    const safeString = (value) => {
      if (value === null || value === undefined) return '';
      return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    };
    
    const url = safeString(results.url);
    const score = safeString(results.score);
    const timestamp = safeString(new Date(results.timestamp || Date.now()).toLocaleString());
    const vulnCount = results.vulnerabilities ? results.vulnerabilities.length : 0;
    
    let domain = 'Unknown Site';
    try {
      domain = new URL(results.url).hostname;
    } catch (e) {
      domain = 'Unknown Site';
    }
    
    let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0, infoCount = 0;
    
    if (results.vulnerabilities && Array.isArray(results.vulnerabilities)) {
      results.vulnerabilities.forEach(v => {
        const severity = (v.severity || 'info').toLowerCase().trim();
        switch(severity) {
          case 'critical': criticalCount++; break;
          case 'high': highCount++; break;
          case 'medium': mediumCount++; break;
          case 'low': lowCount++; break;
          case 'info': infoCount++; break;
          default: infoCount++; break;
        }
      });
    }
    
    let vulnList = '';
    if (results.vulnerabilities && results.vulnerabilities.length > 0) {
      const sortedVulns = results.vulnerabilities
        .sort((a, b) => {
          const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          const aSeverity = (a.severity || 'info').toLowerCase();
          const bSeverity = (b.severity || 'info').toLowerCase();
          return severityOrder[aSeverity] - severityOrder[bSeverity];
        })
        .slice(0, 20);
      
      vulnList = sortedVulns.map(v => {
        const title = safeString(v.title || 'Unknown Vulnerability');
        const description = safeString(v.description || '');
        const recommendation = safeString(v.recommendation || '');
        const severity = (v.severity || 'info').toLowerCase();
        const severityColors = {
          critical: '#e74c3c',
          high: '#e67e22',
          medium: '#f39c12',
          low: '#3498db',
          info: '#2ecc71'
        };
        const severityColor = severityColors[severity] || '#95a5a6';
        
        return `
          <div style="margin-bottom: 20px; padding: 15px; border-left: 4px solid ${severityColor}; background: #f8f9fa;">
            <h4 style="margin: 0 0 10px 0; color: #2c3e50;">${title}</h4>
            <p style="margin: 0 0 8px 0; color: #7f8c8d; font-size: 14px;">${description}</p>
            <p style="margin: 0; color: #27ae60; font-size: 13px; font-style: italic;">💡 ${recommendation}</p>
            <span style="background: ${severityColor}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; text-transform: uppercase;">${severity}</span>
          </div>`;
      }).join('');
      
      if (results.vulnerabilities.length > 20) {
        vulnList += `<p style="text-align: center; color: #7f8c8d; margin-top: 20px;">... and ${results.vulnerabilities.length - 20} more vulnerabilities</p>`;
      }
    } else {
      vulnList = `
        <div style="text-align: center; padding: 40px; background: #d4edda; color: #155724; border-radius: 8px;">
          <h3>✓ No vulnerabilities detected</h3>
          <p>This site appears to follow security best practices</p>
        </div>`;
    }
    
    const report = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NavSec Security Report - ${safeString(domain)}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; color: #2c3e50; }
        .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #2c3e50, #34495e); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { padding: 30px; }
        .score { font-size: 48px; font-weight: bold; margin: 20px 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; margin: 30px 0; }
        .summary-item { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 6px; }
        .summary-value { font-size: 24px; font-weight: bold; margin-bottom: 5px; }
        .summary-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .info-item { padding: 15px; background: #f8f9fa; border-radius: 6px; }
        .info-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; margin-bottom: 5px; }
        .info-value { font-size: 14px; color: #2c3e50; font-weight: 500; }
        .vulnerabilities { margin-top: 40px; }
        .section-title { font-size: 20px; font-weight: 600; color: #2c3e50; margin-bottom: 20px; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ NavSec Security Report</h1>
            <p>Professional Vulnerability Assessment v1.1</p>
        </div>
        
        <div class="content">
            <div style="text-align: center;">
                <div class="score" style="color: ${score >= 80 ? '#27ae60' : score >= 50 ? '#f39c12' : '#e74c3c'};">${score}/100</div>
                <p style="font-size: 18px; color: #7f8c8d;">Security Score</p>
            </div>
            
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Target URL</div>
                    <div class="info-value">${url}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Domain</div>
                    <div class="info-value">${safeString(domain)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Date</div>
                    <div class="info-value">${timestamp}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scanner Version</div>
                    <div class="info-value">NavSec v1.1</div>
                </div>
            </div>
            
            <div class="summary">
                <div class="summary-item">
                    <div class="summary-value" style="color: #e74c3c;">${criticalCount}</div>
                    <div class="summary-label">Critical</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #e67e22;">${highCount}</div>
                    <div class="summary-label">High</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #f39c12;">${mediumCount}</div>
                    <div class="summary-label">Medium</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #3498db;">${lowCount}</div>
                    <div class="summary-label">Low</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #2ecc71;">${infoCount}</div>
                    <div class="summary-label">Info</div>
                </div>
            </div>
            
            <div class="vulnerabilities">
                <h2 class="section-title">Security Findings (${vulnCount} total)</h2>
                ${vulnList}
            </div>
        </div>
        
        <div style="background: #2c3e50; color: white; padding: 20px; text-align: center; border-radius: 0 0 8px 8px;">
            <p style="margin: 0;">NavSec Vulnerability Scanner v1.1 - Report generated on ${timestamp}</p>
        </div>
    </div>
</body>
</html>`;
    
    return report;
    
  } catch (error) {
    console.error('Background: Error generating compact report:', error);
    throw error;
  }
}

// Get stored reports for fallback access
async function getStoredReports() {
  try {
    const allData = await chrome.storage.local.get(null);
    const reports = [];
    
    for (const [key, value] of Object.entries(allData)) {
      if (key.startsWith('export_') && value.content && value.filename) {
        reports.push({
          id: key,
          filename: value.filename,
          timestamp: value.timestamp,
          size: value.content.length,
          date: new Date(value.timestamp).toLocaleString()
        });
      }
    }
    
    reports.sort((a, b) => b.timestamp - a.timestamp);
    return reports;
  } catch (error) {
    console.error('Background: Error getting stored reports:', error);
    throw error;
  }
}

// Download a stored report
async function downloadStoredReport(reportId) {
  try {
    const data = await chrome.storage.local.get(reportId);
    const report = data[reportId];
    
    if (!report || !report.content) {
      throw new Error('Report not found');
    }
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    const downloadResult = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: function(reportContent, filename) {
        try {
          const blob = new Blob([reportContent], { type: 'text/html' });
          const url = URL.createObjectURL(blob);
          
          const link = document.createElement('a');
          link.href = url;
          link.download = filename;
          link.style.display = 'none';
          
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          
          URL.revokeObjectURL(url);
          
          return { success: true };
        } catch (error) {
          return { success: false, error: error.message };
        }
      },
      args: [report.content, report.filename]
    });
    
    if (downloadResult && downloadResult[0] && downloadResult[0].result.success) {
      await chrome.storage.local.remove(reportId);
      return { success: true, message: 'Report downloaded and cleaned up' };
    } else {
      throw new Error('Failed to download stored report');
    }
    
  } catch (error) {
    console.error('Background: Error downloading stored report:', error);
    throw error;
  }
}

// Message listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background: Received message:', request.type, 'from tab:', sender?.tab?.id || 'popup');
  
  if (request.type === 'SCAN_COMPLETE') {
    handleScanResults(request, sender.tab);
    sendResponse({ success: true });
    
  } else if (request.type === 'EXPORT_REPORT') {
    console.log('Background: Export request for tab:', request.tabId);
    
    exportReport(request.tabId)
      .then((result) => {
        console.log('Background: Export completed successfully', result);
        sendResponse({ 
          success: true, 
          message: 'Report exported successfully', 
          downloadId: result.downloadId 
        });
      })
      .catch((error) => {
        console.error('Background: Export failed:', error);
        sendResponse({ 
          success: false, 
          error: error.message || 'Unknown export error' 
        });
      });
    
    return true;
    
  } else if (request.type === 'TEST_XSS_PAYLOAD') {
    handleXSSTest(request, sender.tab);
    sendResponse({ success: true });
    
  } else if (request.type === 'GET_RESULTS_DIRECT') {
    getScanResults(request.tabId).then(results => {
      console.log(`Background: Direct request for tab ${request.tabId}, found:`, !!results);
      sendResponse({ type: 'SCAN_RESULTS', data: results });
    });
    return true;
    
  } else if (request.type === 'GET_STORED_REPORTS') {
    getStoredReports()
      .then((reports) => {
        sendResponse({ success: true, reports });
      })
      .catch((error) => {
        sendResponse({ success: false, error: error.message });
      });
    return true;
    
  } else if (request.type === 'DOWNLOAD_STORED_REPORT') {
    downloadStoredReport(request.reportId)
      .then((result) => {
        sendResponse({ success: true, result });
      })
      .catch((error) => {
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }
  
  return true;
});

async function handleScanResults(results, tab) {
  console.log(`Background: Received scan results for tab ${tab.id}:`, results);
  
  if (results.vulnerabilities) {
    results.vulnerabilities = results.vulnerabilities.map(vuln => ({
      ...vuln,
      severity: (vuln.severity || 'info').toLowerCase()
    }));
  }
  
  await saveScanResults(tab.id, results);
  updateBadge(tab.id, results.score, results.vulnerabilities.length);
  saveScanHistory(results);
  
  if (results.score < 50 || hasCriticalVulnerabilities(results.vulnerabilities)) {
    showNotification(results);
  }
  
  console.log(`Background: Stored results for tab ${tab.id}, total vulnerabilities: ${results.vulnerabilities.length}`);
}

function handleXSSTest(request, tab) {
  getScanResults(tab.id).then(currentResults => {
    if (currentResults && request.success) {
      currentResults.vulnerabilities.push({
        type: 'XSS_VULNERABILITY',
        severity: 'critical',
        title: 'XSS Vulnerability Detected',
        description: `XSS payload executed successfully in ${request.location}`,
        recommendation: 'Implement proper input validation and output encoding',
        evidence: `Payload: ${request.payload}`,
        timestamp: Date.now(),
        url: tab.url
      });
      
      currentResults.score = calculateSecurityScore(currentResults.vulnerabilities);
      saveScanResults(tab.id, currentResults);
      updateBadge(tab.id, currentResults.score, currentResults.vulnerabilities.length);
    }
  });
}

function updateBadge(tabId, score, vulnCount) {
  let badgeText = '';
  let badgeColor = '';
  
  if (vulnCount === 0) {
    badgeText = '✓';
    badgeColor = '#4CAF50';
  } else {
    badgeText = vulnCount.toString();
    
    if (score >= 80) {
      badgeColor = '#FFC107';
    } else if (score >= 50) {
      badgeColor = '#FF9800';
    } else {
      badgeColor = '#F44336';
    }
  }
  
  chrome.action.setBadgeText({
    text: badgeText,
    tabId: tabId
  });
  
  chrome.action.setBadgeBackgroundColor({
    color: badgeColor,
    tabId: tabId
  });
}

function hasCriticalVulnerabilities(vulnerabilities) {
  return vulnerabilities.some(v => v.severity === 'critical' || v.severity === 'high');
}

async function saveScanHistory(results) {
  try {
    const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
    
    scanHistory.push({
      url: results.url,
      domain: new URL(results.url).hostname,
      score: results.score,
      vulnerabilities: results.vulnerabilities.length,
      timestamp: results.timestamp
    });
    
    if (scanHistory.length > 100) {
      scanHistory.shift();
    }
    
    await chrome.storage.local.set({ scanHistory });
  } catch (error) {
    console.error('Background: Error saving scan history:', error);
  }
}

function showNotification(results) {
  try {
    const criticalCount = results.vulnerabilities.filter(v => 
      v.severity === 'critical' || v.severity === 'high'
    ).length;
    
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icon128.png',
      title: '⚠️ Site with Detected Vulnerabilities',
      message: `${results.vulnerabilities.length} vulnerabilities found (${criticalCount} critical/high). Score: ${results.score}/100`,
      priority: 2
    });
  } catch (error) {
    console.error('Background: Error showing notification:', error);
  }
}

function calculateSecurityScore(vulnerabilities) {
  let score = 100;
  
  const penalties = {
    critical: 25,
    high: 15,
    medium: 10,
    low: 5,
    info: 0
  };
  
  vulnerabilities.forEach(vuln => {
    const severity = (vuln.severity || 'info').toLowerCase();
    if (severity !== 'info') {
      score -= penalties[severity] || 5;
    }
  });
  
  return Math.max(0, score);
}

// Clear results when tab is closed
chrome.tabs.onRemoved.addListener(async (tabId) => {
  scanResults.delete(tabId);
  
  if (NAVSEC_CONFIG.FEATURES.USE_STORAGE) {
    try {
      await chrome.storage.local.remove(`scan_${tabId}`);
    } catch (error) {
      console.error('Error clearing storage for tab:', error);
    }
  }
  
  console.log(`Background: Cleared results for closed tab ${tabId}`);
});

// Clear results when tab is reloaded
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    const currentResults = scanResults.get(tabId);
    if (currentResults && currentResults.url) {
      try {
        const oldUrl = new URL(currentResults.url);
        const newUrl = new URL(changeInfo.url);
        
        if (oldUrl.origin !== newUrl.origin || oldUrl.pathname !== newUrl.pathname) {
          scanResults.delete(tabId);
          console.log(`Background: Cleared results for navigated tab ${tabId}`);
          
          chrome.action.setBadgeText({
            text: '',
            tabId: tabId
          });
        }
      } catch (e) {
        scanResults.delete(tabId);
      }
    }
  }
});

// Respond to popup requests
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'popup') {
    port.onMessage.addListener(async (msg) => {
      if (msg.type === 'GET_RESULTS') {
        const results = await getScanResults(msg.tabId);
        console.log(`Background: Sending results for tab ${msg.tabId}:`, results);
        port.postMessage({ type: 'SCAN_RESULTS', data: results });
      }
    });
  }
});

// Security headers analysis via webRequest
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === 'main_frame') {
      checkSecurityHeaders(details);
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

function checkSecurityHeaders(details) {
  const headers = details.responseHeaders;
  const vulnerabilities = [];
  
  const securityHeaders = {
    'x-frame-options': false,
    'strict-transport-security': false,
    'x-content-type-options': false,
    'content-security-policy': false,
    'x-xss-protection': false,
    'referrer-policy': false,
    'permissions-policy': false
  };
  
  headers.forEach(header => {
    const name = header.name.toLowerCase();
    if (name in securityHeaders) {
      securityHeaders[name] = true;
    }
  });
  
  if (!securityHeaders['x-frame-options']) {
    vulnerabilities.push({
      type: 'MISSING_X_FRAME_OPTIONS',
      severity: 'medium',
      title: 'Missing X-Frame-Options Header',
      description: 'Site is vulnerable to clickjacking attacks',
      recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN header'
    });
  }
  
  if (!securityHeaders['strict-transport-security'] && details.url.startsWith('https://')) {
    vulnerabilities.push({
      type: 'MISSING_HSTS',
      severity: 'high',
      title: 'Missing Strict-Transport-Security Header',
      description: 'Site does not enforce HTTPS connections',
      recommendation: 'Add Strict-Transport-Security header with appropriate max-age'
    });
  }
  
  if (!securityHeaders['x-content-type-options']) {
    vulnerabilities.push({
      type: 'MISSING_CONTENT_TYPE_OPTIONS',
      severity: 'low',
      title: 'Missing X-Content-Type-Options Header',
      description: 'Browser may interpret files as different MIME types',
      recommendation: 'Add X-Content-Type-Options: nosniff header'
    });
  }
  
  if (!securityHeaders['referrer-policy']) {
    vulnerabilities.push({
      type: 'MISSING_REFERRER_POLICY',
      severity: 'low',
      title: 'Missing Referrer-Policy Header',
      description: 'Site may leak referrer information',
      recommendation: 'Add Referrer-Policy header with appropriate value'
    });
  }
  
  if (vulnerabilities.length > 0) {
    chrome.tabs.sendMessage(details.tabId, {
      type: 'SECURITY_HEADERS_ANALYSIS',
      headers: securityHeaders,
      analysis: vulnerabilities,
      tls: {
        isHttps: details.url.startsWith('https://'),
        url: details.url
      }
    });
  }
}