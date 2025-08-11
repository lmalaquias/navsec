// content.js - Enhanced Vulnerability Scanner with Bug Fixes
// Author: Leandro Malaquias
// Extension: NavSec Vulnerability Scanner v1.1
(function() {
  'use strict';
  
  // Prevent multiple executions
  if (window.navSecScannerLoaded) {
    console.log('🔍 NavSec Scanner already loaded, skipping...');
    return;
  }
  window.navSecScannerLoaded = true;
  
  console.log('🔍 NavSec Vulnerability Scanner v1.1 STARTING on:', window.location.href);
  
  // Configuration
  const SCANNER_CONFIG = {
    DETECTION_MODE: 'balanced', // 'balanced' or 'paranoid'
    VERSION: '1.1'
  };
  
  // ============= REGIONAL COMPLIANCE MODULE =============
  // Regional compliance configuration
  const REGIONAL_IDENTIFIERS = {
    // Brazil
    BR: {
      name: 'Brazil',
      identifiers: {
        CPF: {
          name: 'CPF (Cadastro de Pessoas Físicas)',
          patterns: [
            /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g,
            /\b\d{11}\b/g // Plain 11 digits
          ],
          validator: validateCPF,
          law: 'LGPD',
          severity: 'critical',
          maxAllowed: 0
        },
        CNPJ: {
          name: 'CNPJ (Cadastro Nacional da Pessoa Jurídica)',
          patterns: [
            /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/g,
            /\b\d{14}\b/g // Plain 14 digits
          ],
          validator: validateCNPJ,
          law: 'LGPD',
          severity: 'high',
          maxAllowed: 1
        }
      }
    },
    
    // United States
    US: {
      name: 'United States',
      identifiers: {
        SSN: {
          name: 'SSN (Social Security Number)',
          patterns: [
            /\b\d{3}-\d{2}-\d{4}\b/g,
            /\b\d{3}\s\d{2}\s\d{4}\b/g,
            /\b\d{9}\b/g // Plain 9 digits (needs context)
          ],
          validator: validateSSN,
          law: 'CCPA/HIPAA',
          severity: 'critical',
          maxAllowed: 0
        },
        EIN: {
          name: 'EIN (Employer Identification Number)',
          patterns: [
            /\b\d{2}-\d{7}\b/g
          ],
          validator: validateEIN,
          law: 'Privacy Act',
          severity: 'high',
          maxAllowed: 1
        }
      }
    },
    
    // European Union
    EU: {
      name: 'European Union',
      identifiers: {
        // France
        INSEE: {
          name: 'INSEE (French Social Security)',
          patterns: [
            /\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\b/g
          ],
          validator: validateINSEE,
          law: 'GDPR',
          severity: 'critical',
          maxAllowed: 0
        },
        // Germany
        STEUERID: {
          name: 'Steueridentifikationsnummer (German Tax ID)',
          patterns: [
            /\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b/g
          ],
          validator: validateSteuerID,
          law: 'GDPR',
          severity: 'critical',
          maxAllowed: 0
        },
        // Spain
        DNI: {
          name: 'DNI (Spanish National ID)',
          patterns: [
            /\b\d{8}-?[A-Z]\b/g,
            /\b[XYZ]\d{7}[A-Z]\b/g // NIE for foreigners
          ],
          validator: validateDNI,
          law: 'GDPR',
          severity: 'critical',
          maxAllowed: 0
        },
        // Italy
        CF: {
          name: 'Codice Fiscale (Italian Tax Code)',
          patterns: [
            /\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b/gi
          ],
          validator: validateCodiceFiscale,
          law: 'GDPR',
          severity: 'critical',
          maxAllowed: 0
        }
      }
    },
    
    // United Kingdom
    UK: {
      name: 'United Kingdom',
      identifiers: {
        NINO: {
          name: 'NINO (National Insurance Number)',
          patterns: [
            /\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b/gi
          ],
          validator: validateNINO,
          law: 'UK GDPR',
          severity: 'critical',
          maxAllowed: 0
        },
        NHS: {
          name: 'NHS Number',
          patterns: [
            /\b\d{3}\s?\d{3}\s?\d{4}\b/g,
            /\b\d{10}\b/g
          ],
          validator: validateNHS,
          law: 'UK GDPR',
          severity: 'critical',
          maxAllowed: 0
        }
      }
    },
    
    // Canada
    CA: {
      name: 'Canada',
      identifiers: {
        SIN: {
          name: 'SIN (Social Insurance Number)',
          patterns: [
            /\b\d{3}-\d{3}-\d{3}\b/g,
            /\b\d{3}\s\d{3}\s\d{3}\b/g,
            /\b\d{9}\b/g
          ],
          validator: validateSIN,
          law: 'PIPEDA',
          severity: 'critical',
          maxAllowed: 0
        }
      }
    },
    
    // Australia
    AU: {
      name: 'Australia',
      identifiers: {
        TFN: {
          name: 'TFN (Tax File Number)',
          patterns: [
            /\b\d{3}\s?\d{3}\s?\d{3}\b/g,
            /\b\d{9}\b/g
          ],
          validator: validateTFN,
          law: 'Privacy Act',
          severity: 'critical',
          maxAllowed: 0
        },
        MEDICARE: {
          name: 'Medicare Number',
          patterns: [
            /\b\d{4}\s?\d{5}\s?\d{1}\b/g,
            /\b\d{10}\b/g
          ],
          validator: validateMedicare,
          law: 'Privacy Act',
          severity: 'critical',
          maxAllowed: 0
        }
      }
    },
    
    // India
    IN: {
      name: 'India',
      identifiers: {
        AADHAAR: {
          name: 'Aadhaar Number',
          patterns: [
            /\b\d{4}\s?\d{4}\s?\d{4}\b/g,
            /\b\d{12}\b/g
          ],
          validator: validateAadhaar,
          law: 'IT Act',
          severity: 'critical',
          maxAllowed: 0
        },
        PAN: {
          name: 'PAN (Permanent Account Number)',
          patterns: [
            /\b[A-Z]{5}\d{4}[A-Z]\b/g
          ],
          validator: validatePAN,
          law: 'IT Act',
          severity: 'high',
          maxAllowed: 0
        }
      }
    },
    
    // Japan
    JP: {
      name: 'Japan',
      identifiers: {
        MYNUMBER: {
          name: 'My Number (個人番号)',
          patterns: [
            /\b\d{4}\s?\d{4}\s?\d{4}\b/g,
            /\b\d{12}\b/g
          ],
          validator: validateMyNumber,
          law: 'APPI',
          severity: 'critical',
          maxAllowed: 0
        }
      }
    },
    
    // South Korea
    KR: {
      name: 'South Korea',
      identifiers: {
        RRN: {
          name: 'RRN (Resident Registration Number)',
          patterns: [
            /\b\d{6}-\d{7}\b/g,
            /\b\d{13}\b/g
          ],
          validator: validateRRN,
          law: 'PIPA',
          severity: 'critical',
          maxAllowed: 0
        }
      }
    },
    
    // Mexico
    MX: {
      name: 'Mexico',
      identifiers: {
        CURP: {
          name: 'CURP (Clave Única de Registro de Población)',
          patterns: [
            /\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b/g
          ],
          validator: validateCURP,
          law: 'LFPDPPP',
          severity: 'critical',
          maxAllowed: 0
        },
        RFC: {
          name: 'RFC (Registro Federal de Contribuyentes)',
          patterns: [
            /\b[A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3}\b/g
          ],
          validator: validateRFC,
          law: 'LFPDPPP',
          severity: 'high',
          maxAllowed: 1
        }
      }
    }
  };
  
  // Validation Functions
  
  // Brazil - CPF (Enhanced)
  function validateCPF(cpf) {
    cpf = cpf.replace(/[^\d]/g, '');
    if (cpf.length !== 11) return false;
    
    // Expanded list of invalid CPFs
    const invalidCPFs = [
      '00000000000', '11111111111', '22222222222',
      '33333333333', '44444444444', '55555555555',
      '66666666666', '77777777777', '88888888888',
      '99999999999', '12345678909', '01234567890'
    ];
    
    if (invalidCPFs.includes(cpf)) return false;
    
    // Checksum validation
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      sum += parseInt(cpf[i]) * (10 - i);
    }
    let digit1 = 11 - (sum % 11);
    if (digit1 > 9) digit1 = 0;
    if (parseInt(cpf[9]) !== digit1) return false;
    
    sum = 0;
    for (let i = 0; i < 10; i++) {
      sum += parseInt(cpf[i]) * (11 - i);
    }
    let digit2 = 11 - (sum % 11);
    if (digit2 > 9) digit2 = 0;
    if (parseInt(cpf[10]) !== digit2) return false;
    
    return true;
  }
  
  // Brazil - CNPJ
  function validateCNPJ(cnpj) {
    cnpj = cnpj.replace(/[^\d]/g, '');
    if (cnpj.length !== 14) return false;
    
    // Checksum validation
    let sum = 0;
    let weight = [5,4,3,2,9,8,7,6,5,4,3,2];
    for (let i = 0; i < 12; i++) {
      sum += parseInt(cnpj[i]) * weight[i];
    }
    let digit1 = sum % 11 < 2 ? 0 : 11 - (sum % 11);
    if (parseInt(cnpj[12]) !== digit1) return false;
    
    sum = 0;
    weight = [6,5,4,3,2,9,8,7,6,5,4,3,2];
    for (let i = 0; i < 13; i++) {
      sum += parseInt(cnpj[i]) * weight[i];
    }
    let digit2 = sum % 11 < 2 ? 0 : 11 - (sum % 11);
    if (parseInt(cnpj[13]) !== digit2) return false;
    
    return true;
  }
  
  // USA - SSN
  function validateSSN(ssn) {
    ssn = ssn.replace(/[^\d]/g, '');
    if (ssn.length !== 9) return false;
    
    // Invalid SSN patterns
    if (ssn === '000000000' || ssn === '999999999') return false;
    if (ssn.substring(0, 3) === '000' || ssn.substring(0, 3) === '666') return false;
    if (ssn.substring(3, 5) === '00' || ssn.substring(5, 9) === '0000') return false;
    
    return true;
  }
  
  // USA - EIN
  function validateEIN(ein) {
    ein = ein.replace(/[^\d]/g, '');
    return ein.length === 9 && /^[0-9]{2}[0-9]{7}$/.test(ein);
  }
  
  // Canada - SIN
  function validateSIN(sin) {
    sin = sin.replace(/[^\d]/g, '');
    if (sin.length !== 9) return false;
    
    // Luhn algorithm
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      let digit = parseInt(sin[i]);
      if (i % 2 === 1) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
    }
    
    return sum % 10 === 0;
  }
  
  // UK - NINO
  function validateNINO(nino) {
    nino = nino.replace(/\s/g, '').toUpperCase();
    
    // Format: 2 letters, 6 numbers, 1 letter
    if (!/^[A-Z]{2}\d{6}[A-Z]$/.test(nino)) return false;
    
    // Invalid prefixes
    const invalidPrefixes = ['BG', 'GB', 'NK', 'KN', 'TN', 'NT', 'ZZ'];
    if (invalidPrefixes.includes(nino.substring(0, 2))) return false;
    
    // First or second letter cannot be O
    if (nino[0] === 'O' || nino[1] === 'O') return false;
    
    return true;
  }
  
  // UK - NHS
  function validateNHS(nhs) {
    nhs = nhs.replace(/[^\d]/g, '');
    if (nhs.length !== 10) return false;
    
    // Modulus 11 algorithm
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      sum += parseInt(nhs[i]) * (10 - i);
    }
    let checkDigit = 11 - (sum % 11);
    if (checkDigit === 11) checkDigit = 0;
    
    return parseInt(nhs[9]) === checkDigit;
  }
  
  // Australia - TFN
  function validateTFN(tfn) {
    tfn = tfn.replace(/[^\d]/g, '');
    if (tfn.length !== 9) return false;
    
    // Modulus 11 with specific weights
    const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      sum += parseInt(tfn[i]) * weights[i];
    }
    
    return sum % 11 === 0;
  }
  
  // Australia - Medicare
  function validateMedicare(medicare) {
    medicare = medicare.replace(/[^\d]/g, '');
    return medicare.length === 10 && /^[2-6]\d{9}$/.test(medicare);
  }
  
  // Spain - DNI/NIE
  function validateDNI(dni) {
    dni = dni.replace(/-/g, '').toUpperCase();
    
    const letterMap = 'TRWAGMYFPDXBNJZSQVHLCKE';
    
    if (/^\d{8}[A-Z]$/.test(dni)) {
      // DNI format
      const number = parseInt(dni.substring(0, 8));
      const letter = dni[8];
      return letterMap[number % 23] === letter;
    } else if (/^[XYZ]\d{7}[A-Z]$/.test(dni)) {
      // NIE format
      let number = dni.substring(1, 8);
      const firstLetter = dni[0];
      const lastLetter = dni[8];
      
      // Convert first letter to number
      if (firstLetter === 'X') number = '0' + number;
      else if (firstLetter === 'Y') number = '1' + number;
      else if (firstLetter === 'Z') number = '2' + number;
      
      return letterMap[parseInt(number) % 23] === lastLetter;
    }
    
    return false;
  }
  
  // France - INSEE
  function validateINSEE(insee) {
    insee = insee.replace(/\s/g, '');
    if (insee.length !== 15) return false;
    
    // Basic format check
    if (!/^[12]\d{14}$/.test(insee)) return false;
    
    // Extract components
    const key = parseInt(insee.substring(13, 15));
    const number = insee.substring(0, 13);
    
    // Calculate checksum
    const calculatedKey = 97 - (parseInt(number) % 97);
    
    return key === calculatedKey;
  }
  
  // Germany - Steuer ID
  function validateSteuerID(steuerid) {
    steuerid = steuerid.replace(/\s/g, '');
    if (steuerid.length !== 11) return false;
    
    // Check digit validation
    let product = 10;
    for (let i = 0; i < 10; i++) {
      let sum = (parseInt(steuerid[i]) + product) % 10;
      if (sum === 0) sum = 10;
      product = (sum * 2) % 11;
    }
    
    let checkDigit = 11 - product;
    if (checkDigit === 10) checkDigit = 0;
    
    return parseInt(steuerid[10]) === checkDigit;
  }
  
  // Italy - Codice Fiscale
  function validateCodiceFiscale(cf) {
    cf = cf.toUpperCase();
    if (cf.length !== 16) return false;
    
    // Complex validation - simplified version
    return /^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/.test(cf);
  }
  
  // India - Aadhaar
  function validateAadhaar(aadhaar) {
    aadhaar = aadhaar.replace(/\s/g, '');
    if (aadhaar.length !== 12) return false;
    
    // Verhoeff algorithm
    const d = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
               [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
               [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
               [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
               [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
               [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
               [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
               [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
               [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
               [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]];
    
    const p = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
               [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
               [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
               [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
               [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
               [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
               [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]];
    
    let c = 0;
    const reversedAadhaar = aadhaar.split('').reverse();
    
    for (let i = 0; i < reversedAadhaar.length; i++) {
      c = d[c][p[i % 8][parseInt(reversedAadhaar[i])]];
    }
    
    return c === 0;
  }
  
  // India - PAN
  function validatePAN(pan) {
    return /^[A-Z]{5}\d{4}[A-Z]$/.test(pan.toUpperCase());
  }
  
  // Japan - My Number
  function validateMyNumber(mynumber) {
    mynumber = mynumber.replace(/\s/g, '');
    if (mynumber.length !== 12) return false;
    
    // Check digit validation
    let sum = 0;
    for (let i = 0; i < 11; i++) {
      const n = 11 - i;
      const p = n <= 6 ? n + 1 : n - 5;
      sum += parseInt(mynumber[i]) * p;
    }
    
    const remainder = sum % 11;
    const checkDigit = remainder <= 1 ? 0 : 11 - remainder;
    
    return parseInt(mynumber[11]) === checkDigit;
  }
  
  // South Korea - RRN
  function validateRRN(rrn) {
    rrn = rrn.replace(/-/g, '');
    if (rrn.length !== 13) return false;
    
    // Checksum validation
    const weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum = 0;
    
    for (let i = 0; i < 12; i++) {
      sum += parseInt(rrn[i]) * weights[i];
    }
    
    const checkDigit = (11 - (sum % 11)) % 10;
    return parseInt(rrn[12]) === checkDigit;
  }
  
  // Mexico - CURP
  function validateCURP(curp) {
    return /^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$/.test(curp.toUpperCase());
  }
  
  // Mexico - RFC
  function validateRFC(rfc) {
    rfc = rfc.toUpperCase();
    
    // For individuals (13 characters)
    if (rfc.length === 13) {
      return /^[A-Z&Ñ]{4}\d{6}[A-Z0-9]{3}$/.test(rfc);
    }
    // For companies (12 characters)
    else if (rfc.length === 12) {
      return /^[A-Z&Ñ]{3}\d{6}[A-Z0-9]{3}$/.test(rfc);
    }
    
    return false;
  }
  
  // Main detection class
  class RegionalComplianceDetector {
    constructor(regions = ['ALL']) {
      this.activeRegions = regions;
      this.detectionResults = [];
    }
    
    // Set active regions
    setRegions(regions) {
      this.activeRegions = regions;
    }
    
    // Get active regions based on user locale or manual selection
    getActiveRegions() {
      if (this.activeRegions.includes('ALL')) {
        return Object.keys(REGIONAL_IDENTIFIERS);
      }
      return this.activeRegions;
    }
    
    // Detect regional identifiers in content
    detectIdentifiers(content) {
      const results = [];
      const activeRegions = this.getActiveRegions();
      
      activeRegions.forEach(region => {
        if (!REGIONAL_IDENTIFIERS[region]) return;
        
        const regionData = REGIONAL_IDENTIFIERS[region];
        
        Object.entries(regionData.identifiers).forEach(([idType, config]) => {
          config.patterns.forEach(pattern => {
            const matches = content.match(pattern) || [];
            
            matches.forEach(match => {
              // Validate if validator exists
              if (config.validator && config.validator(match)) {
                results.push({
                  region: region,
                  regionName: regionData.name,
                  type: idType,
                  name: config.name,
                  value: this.maskIdentifier(match, idType),
                  law: config.law,
                  severity: config.severity,
                  match: match
                });
              } else if (!config.validator) {
                // If no validator, consider it a potential match
                results.push({
                  region: region,
                  regionName: regionData.name,
                  type: idType,
                  name: config.name,
                  value: this.maskIdentifier(match, idType),
                  law: config.law,
                  severity: config.severity,
                  match: match,
                  unvalidated: true
                });
              }
            });
          });
        });
      });
      
      // Remove duplicates
      const uniqueResults = this.removeDuplicates(results);
      this.detectionResults = uniqueResults;
      
      return uniqueResults;
    }
    
    // Mask identifier for privacy
    maskIdentifier(identifier, type) {
      const cleaned = identifier.replace(/[\s-./]/g, '');
      const length = cleaned.length;
      
      if (length <= 4) {
        return '*'.repeat(length);
      } else if (length <= 8) {
        return cleaned.substring(0, 2) + '*'.repeat(length - 2);
      } else {
        return cleaned.substring(0, 3) + '*'.repeat(length - 6) + cleaned.substring(length - 3);
      }
    }
    
    // Remove duplicate detections
    removeDuplicates(results) {
      const seen = new Set();
      return results.filter(result => {
        const key = `${result.region}-${result.type}-${result.match}`;
        if (seen.has(key)) {
          return false;
        }
        seen.add(key);
        return true;
      });
    }
    
    // Generate vulnerabilities for NavSec
    generateVulnerabilities() {
      const vulnerabilities = [];
      
      // Group by region and type
      const grouped = {};
      this.detectionResults.forEach(result => {
        const key = `${result.region}-${result.type}`;
        if (!grouped[key]) {
          grouped[key] = [];
        }
        grouped[key].push(result);
      });
      
      // Create vulnerabilities
      Object.entries(grouped).forEach(([key, detections]) => {
        const first = detections[0];
        const config = REGIONAL_IDENTIFIERS[first.region].identifiers[first.type];
        
        // Check if exceeds allowed threshold
        if (detections.length > config.maxAllowed) {
          vulnerabilities.push({
            type: `EXPOSED_${first.type}`,
            severity: first.severity,
            title: `${first.name} Exposed`,
            description: `Found ${detections.length} instance(s) of ${first.name} (${first.regionName}) in page content`,
            recommendation: `Remove ${first.name} from client-side code. This violates ${first.law} regulations.`,
            evidence: `Found ${detections.length} instance(s). Examples: ${detections.slice(0, 3).map(d => d.value).join(', ')}`,
            compliance: {
              law: first.law,
              region: first.regionName,
              identifierType: first.name
            }
          });
        }
      });
      
      return vulnerabilities;
    }
    
    // Get compliance summary
    getComplianceSummary() {
      const summary = {
        totalIdentifiersFound: this.detectionResults.length,
        byRegion: {},
        bySeverity: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        },
        laws: new Set()
      };
      
      this.detectionResults.forEach(result => {
        // By region
        if (!summary.byRegion[result.regionName]) {
          summary.byRegion[result.regionName] = 0;
        }
        summary.byRegion[result.regionName]++;
        
        // By severity
        summary.bySeverity[result.severity]++;
        
        // Laws
        summary.laws.add(result.law);
      });
      
      summary.laws = Array.from(summary.laws);
      
      return summary;
    }
  }
  // ============= END REGIONAL COMPLIANCE MODULE =============
  
  class VulnerabilityScanner {
    constructor() {
      this.vulnerabilities = [];
      this.securityHeaders = null;
      this.tlsInfo = null;
      this.headerAnalysis = [];
      this.scanComplete = false;
      this.listenerAdded = false;
      
      console.log('Content: Scanner instance created v1.1');
      
      // Prevent duplicate listeners
      if (!window.navSecListenerAdded) {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
          if (request.type === 'SECURITY_HEADERS_ANALYSIS') {
            console.log('Content: Received header analysis from background:', request);
            this.securityHeaders = request.headers;
            this.tlsInfo = request.tls;
            this.headerAnalysis = request.analysis || [];
            this.processHeaderAnalysis();
            sendResponse({ success: true });
          }
          return true;
        });
        window.navSecListenerAdded = true;
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
      
      console.log('Content: Starting comprehensive vulnerability analysis v1.1...');
      
      try {
        // Core security checks
        this.checkHTTPS();
        this.checkInsecureForms();
        this.checkMixedContent();
        this.checkOutdatedLibraries();
        this.checkCSP();
        this.checkExternalLinks();
        
        // XSS checks
        this.checkBasicXSS();
        
        // Authentication checks
        this.checkBasicAuth();
        
        // SQL Injection checks
        this.checkSQLInjection();
        
        // Additional security checks
        this.checkCookieSecurity();
        this.checkAPIsAndCORS();
        this.checkSubresourceIntegrity();
        this.checkSensitiveInformation();
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
    
    // Helper function for storage check
    checkStorageForSensitiveData() {
      try {
        const sensitiveKeys = [
          'password', 'token', 'api_key', 'apikey', 'secret', 
          'private', 'card', 'cvv', 'ssn', 'cpf'
        ];
        
        // Check localStorage
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          const value = localStorage.getItem(key);
          
          sensitiveKeys.forEach(sensitive => {
            if (key && (key.toLowerCase().includes(sensitive) || 
                (value && value.toLowerCase().includes(sensitive)))) {
              this.addVulnerability({
                type: 'SENSITIVE_DATA_IN_STORAGE',
                severity: 'high',
                title: 'Sensitive data in localStorage',
                description: `Potentially sensitive data found in localStorage key: "${key}"`,
                recommendation: 'Never store sensitive data in client-side storage',
                evidence: `Key: ${key}`
              });
              return; // Only report once per key
            }
          });
        }
        
      } catch (e) {
        // Storage not accessible
      }
    }
    
    // HTML/JS COMMENT SCANNER
    checkCommentsForSensitiveInfo() {
      try {
        console.log('Content: Scanning comments for sensitive information...');
        
        // Get all comments from HTML
        const commentWalker = document.createTreeWalker(
          document.body,
          NodeFilter.SHOW_COMMENT,
          null,
          false
        );
        
        const sensitivePatterns = [
          { pattern: /todo.*password/i, type: 'TODO_WITH_PASSWORD' },
          { pattern: /todo.*api/i, type: 'TODO_WITH_API' },
          { pattern: /fixme.*security/i, type: 'FIXME_SECURITY' },
          { pattern: /hack|workaround/i, type: 'HACK_COMMENT' },
          { pattern: /(dev|development|staging|test)\.([\w-]+\.)+[\w]+/i, type: 'DEV_URL_IN_COMMENT' },
          { pattern: /\b(admin|root|test)[:=]["']?\w+/i, type: 'CREDS_IN_COMMENT' },
          { pattern: /localhost:\d+/i, type: 'LOCALHOST_IN_COMMENT' },
          { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/i, type: 'IP_IN_COMMENT' }
        ];
        
        let comment;
        let issuesFound = [];
        
        while (comment = commentWalker.nextNode()) {
          const text = comment.nodeValue;
          
          sensitivePatterns.forEach(({ pattern, type }) => {
            if (pattern.test(text)) {
              issuesFound.push({
                type: type,
                content: text.substring(0, 100) + (text.length > 100 ? '...' : '')
              });
            }
          });
        }
        
        // Check JavaScript comments
        const scripts = document.querySelectorAll('script');
        scripts.forEach(script => {
          const content = script.textContent || script.innerHTML || '';
          
          // Match single-line and multi-line comments
          const jsComments = content.match(/\/\/.*$|\/\*[\s\S]*?\*\//gm) || [];
          
          jsComments.forEach(comment => {
            sensitivePatterns.forEach(({ pattern, type }) => {
              if (pattern.test(comment)) {
                issuesFound.push({
                  type: type,
                  content: comment.substring(0, 100) + (comment.length > 100 ? '...' : '')
                });
              }
            });
          });
        });
        
        // Report findings
        if (issuesFound.length > 0) {
          const grouped = issuesFound.reduce((acc, issue) => {
            acc[issue.type] = (acc[issue.type] || 0) + 1;
            return acc;
          }, {});
          
          Object.entries(grouped).forEach(([type, count]) => {
            const titles = {
              'TODO_WITH_PASSWORD': 'TODO comments mentioning passwords',
              'TODO_WITH_API': 'TODO comments mentioning API',
              'FIXME_SECURITY': 'FIXME comments about security',
              'HACK_COMMENT': 'Hack/workaround comments found',
              'DEV_URL_IN_COMMENT': 'Development URLs in comments',
              'CREDS_IN_COMMENT': 'Possible credentials in comments',
              'LOCALHOST_IN_COMMENT': 'Localhost references in comments',
              'IP_IN_COMMENT': 'IP addresses in comments'
            };
            
            this.addVulnerability({
              type: `COMMENT_${type}`,
              severity: type.includes('CREDS') || type.includes('PASSWORD') ? 'high' : 'medium',
              title: titles[type] || 'Sensitive information in comments',
              description: `Found ${count} comment(s) containing potentially sensitive information`,
              recommendation: 'Remove all sensitive information from production code comments',
              evidence: `${count} instance(s) found`
            });
          });
        }
        
      } catch (error) {
        console.error('Content: Error scanning comments:', error);
      }
    }
    
    // WEBSOCKET SECURITY CHECK
    checkWebSocketSecurity() {
      try {
        console.log('Content: Checking WebSocket security...');
        
        // Check for WebSocket usage
        const scripts = document.querySelectorAll('script');
        let wsUsage = false;
        let insecureWs = false;
        
        scripts.forEach(script => {
          const content = script.textContent || script.innerHTML || '';
          
          // Check for WebSocket instantiation
          if (/new\s+WebSocket\s*\(/i.test(content)) {
            wsUsage = true;
            
            // Check for insecure ws://
            if (/new\s+WebSocket\s*\(\s*["']ws:\/\//i.test(content)) {
              insecureWs = true;
            }
          }
        });
        
        if (insecureWs) {
          this.addVulnerability({
            type: 'INSECURE_WEBSOCKET',
            severity: 'high',
            title: 'Insecure WebSocket connection',
            description: 'WebSocket connections using ws:// instead of wss:// (unencrypted)',
            recommendation: 'Use wss:// for all WebSocket connections to ensure encryption',
            evidence: 'Unencrypted WebSocket usage detected'
          });
        } else if (wsUsage && window.location.protocol === 'https:') {
          this.addVulnerability({
            type: 'WEBSOCKET_DETECTED',
            severity: 'info',
            title: 'WebSocket usage detected',
            description: 'Site uses WebSocket connections - verify they use wss:// protocol',
            recommendation: 'Ensure all WebSocket connections use wss:// for encryption'
          });
        }
        
      } catch (error) {
        console.error('Content: Error checking WebSocket security:', error);
      }
    }
    
    // IFRAME SECURITY ANALYZER
    checkIframeSecurity() {
      try {
        console.log('Content: Analyzing iframe security...');
        
        const iframes = document.querySelectorAll('iframe');
        
        if (iframes.length > 0) {
          let insecureIframes = [];
          let sandboxMissing = [];
          let externalIframes = [];
          
          iframes.forEach((iframe, index) => {
            const src = iframe.src || iframe.getAttribute('src') || 'inline';
            
            // Check for sandbox attribute
            if (!iframe.sandbox || iframe.sandbox.length === 0) {
              sandboxMissing.push(src);
            }
            
            // Check for external iframes
            if (src && src !== 'inline') {
              try {
                const url = new URL(src);
                if (url.origin !== window.location.origin) {
                  externalIframes.push(src);
                }
              } catch (e) {
                // Invalid URL
              }
            }
            
            // Check for insecure protocols
            if (src && src.startsWith('http://') && window.location.protocol === 'https:') {
              insecureIframes.push(src);
            }
          });
          
          if (sandboxMissing.length > 0) {
            this.addVulnerability({
              type: 'IFRAME_NO_SANDBOX',
              severity: 'medium',
              title: 'Iframes without sandbox attribute',
              description: `${sandboxMissing.length} iframe(s) without sandbox restrictions`,
              recommendation: 'Add sandbox attribute to all iframes with minimal required permissions',
              evidence: `${sandboxMissing.length} unsandboxed iframe(s)`
            });
          }
          
          if (externalIframes.length > 0) {
            this.addVulnerability({
              type: 'EXTERNAL_IFRAMES',
              severity: 'medium',
              title: 'External iframes detected',
              description: `${externalIframes.length} iframe(s) loading content from external domains`,
              recommendation: 'Verify all external iframe sources are trusted and use sandbox attribute',
              evidence: `External domains: ${[...new Set(externalIframes.map(url => {
                try { return new URL(url).hostname; } catch(e) { return 'unknown'; }
              }))].join(', ')}`
            });
          }
          
          if (insecureIframes.length > 0) {
            this.addVulnerability({
              type: 'INSECURE_IFRAME',
              severity: 'high',
              title: 'Iframes loading via HTTP',
              description: 'Iframe content loaded without encryption on HTTPS page',
              recommendation: 'Use HTTPS for all iframe sources',
              evidence: `${insecureIframes.length} insecure iframe(s)`
            });
          }
        }
        
      } catch (error) {
        console.error('Content: Error checking iframe security:', error);
      }
    }
    
    // ADVANCED FORM SECURITY ANALYZER
    checkAdvancedFormSecurity() {
      try {
        console.log('Content: Analyzing advanced form security...');
        
        const forms = document.querySelectorAll('form');
        
        forms.forEach((form, index) => {
          // Check for credit card fields without tokenization hint
          const ccFields = form.querySelectorAll('input[name*="card"], input[name*="credit"], input[placeholder*="card number"]');
          if (ccFields.length > 0) {
            this.addVulnerability({
              type: 'CREDIT_CARD_FORM',
              severity: 'high',
              title: 'Credit card form detected',
              description: 'Form appears to collect credit card information',
              recommendation: 'Implement PCI-compliant tokenization and never store card data',
              evidence: `${ccFields.length} credit card field(s) found`
            });
          }
          
          // Check for file upload without type restriction
          const fileInputs = form.querySelectorAll('input[type="file"]');
          fileInputs.forEach(input => {
            if (!input.accept) {
              this.addVulnerability({
                type: 'UNRESTRICTED_FILE_UPLOAD',
                severity: 'medium',
                title: 'File upload without type restriction',
                description: 'File input allows any file type to be uploaded',
                recommendation: 'Add accept attribute to restrict allowed file types',
                evidence: `Form ${index + 1} has unrestricted file upload`
              });
            }
          });
          
          // Check for password fields without strength indicator
          const passwordFields = form.querySelectorAll('input[type="password"]');
          if (passwordFields.length > 0) {
            const hasStrengthIndicator = form.querySelector('[class*="strength"], [id*="strength"], [data-strength]');
            if (!hasStrengthIndicator) {
              this.addVulnerability({
                type: 'NO_PASSWORD_STRENGTH',
                severity: 'low',
                title: 'Password field without strength indicator',
                description: 'No password strength feedback for users',
                recommendation: 'Add password strength indicator to guide users',
                evidence: `${passwordFields.length} password field(s) without strength feedback`
              });
            }
          }
          
          // Check for autocomplete on sensitive fields
          const sensitiveFields = form.querySelectorAll('input[type="password"], input[name*="ssn"], input[name*="cpf"], input[name*="card"]');
          sensitiveFields.forEach(field => {
            if (field.autocomplete !== 'off' && field.autocomplete !== 'new-password') {
              this.addVulnerability({
                type: 'AUTOCOMPLETE_SENSITIVE',
                severity: 'medium',
                title: 'Autocomplete enabled on sensitive field',
                description: 'Sensitive form fields allow browser autocomplete',
                recommendation: 'Set autocomplete="off" on sensitive fields',
                evidence: `Field: ${field.name || field.type}`
              });
              return; // Only report once
            }
          });
          
          // Check for CAPTCHA on critical forms
          const isLoginForm = form.querySelector('input[type="password"]') && form.querySelector('input[type="email"], input[type="text"][name*="user"]');
          const isRegistrationForm = form.querySelector('input[name*="confirm"], input[name*="register"]');
          
          if ((isLoginForm || isRegistrationForm) && !form.querySelector('[class*="captcha"], [id*="captcha"], [name*="captcha"], .g-recaptcha')) {
            this.addVulnerability({
              type: 'NO_CAPTCHA',
              severity: 'medium',
              title: 'Critical form without CAPTCHA',
              description: 'Login/registration form lacks bot protection',
              recommendation: 'Implement CAPTCHA to prevent automated attacks',
              evidence: isLoginForm ? 'Login form' : 'Registration form'
            });
          }
        });
        
      } catch (error) {
        console.error('Content: Error in advanced form security check:', error);
      }
    }
    
    // META TAGS AND SEO SECURITY
    checkMetaTagsSecurity() {
      try {
        console.log('Content: Checking meta tags and SEO security...');
        
        // Check robots.txt reference
        const robotsMeta = document.querySelector('meta[name="robots"]');
        if (robotsMeta && robotsMeta.content.includes('noindex')) {
          this.addVulnerability({
            type: 'NOINDEX_META',
            severity: 'info',
            title: 'Page marked as noindex',
            description: 'This page is hidden from search engines',
            recommendation: 'Verify if this is intentional for sensitive pages'
          });
        }
        
        // Check for exposed system information in meta tags
        const generatorMeta = document.querySelector('meta[name="generator"]');
        if (generatorMeta) {
          this.addVulnerability({
            type: 'GENERATOR_META_EXPOSED',
            severity: 'low',
            title: 'CMS/Framework information exposed',
            description: `Generator meta tag reveals: ${generatorMeta.content}`,
            recommendation: 'Remove generator meta tag to hide system information',
            evidence: generatorMeta.content
          });
        }
        
        // Check Open Graph tags for internal URLs
        const ogTags = document.querySelectorAll('meta[property^="og:"]');
        ogTags.forEach(tag => {
          const content = tag.content;
          if (content && (content.includes('localhost') || content.includes('192.168') || content.includes('10.0'))) {
            this.addVulnerability({
              type: 'INTERNAL_URL_IN_OG',
              severity: 'medium',
              title: 'Internal URL in Open Graph tags',
              description: 'Open Graph meta tags contain internal/development URLs',
              recommendation: 'Update Open Graph URLs to use production domains',
              evidence: `${tag.property}: ${content}`
            });
            return; // Only report once
          }
        });
        
        // Check for author information disclosure
        const authorMeta = document.querySelector('meta[name="author"]');
        if (authorMeta && authorMeta.content.includes('@')) {
          this.addVulnerability({
            type: 'AUTHOR_EMAIL_EXPOSED',
            severity: 'low',
            title: 'Author email in meta tags',
            description: 'Author meta tag contains email address',
            recommendation: 'Consider removing email from public meta tags',
            evidence: authorMeta.content
          });
        }
        
      } catch (error) {
        console.error('Content: Error checking meta tags security:', error);
      }
    }
    
    // Simplified XSS check (Fixed severity)
    checkBasicXSS() {
      try {
        // Check URL parameters for potential XSS
        const urlParams = new URLSearchParams(window.location.search);
        let xssFound = false;
        
        urlParams.forEach((value, key) => {
          if (value.length > 3 && document.body && document.body.innerHTML.includes(value) && !xssFound) {
            this.addVulnerability({
              type: 'REFLECTED_XSS_PARAM',
              severity: 'critical', // Changed from 'high' to 'critical'
              title: 'Potential Reflected XSS in URL parameter',
              description: `URL parameter "${key}" appears to be reflected in page content`,
              recommendation: 'Implement proper input validation and output encoding',
              evidence: `Parameter: ${key}=${value.substring(0, 50)}...`
            });
            xssFound = true; // Only report once
          }
        });
        
        // Check for dangerous event handlers
        const dangerousHandlers = document.querySelectorAll('[onclick], [onload], [onerror], [onmouseover], [onfocus]');
        if (dangerousHandlers.length > 0) {
          this.addVulnerability({
            type: 'UNSAFE_EVENT_HANDLER',
            severity: 'medium',
            title: 'Inline event handlers detected',
            description: 'Event handlers in HTML may process user input unsafely',
            recommendation: 'Use addEventListener with proper validation',
            evidence: `Found ${dangerousHandlers.length} inline event handlers`
          });
        }
      } catch (error) {
        console.error('Content: Error in XSS check:', error);
      }
    }
    
    // Simplified auth check
    checkBasicAuth() {
      try {
        // Check for login forms
        const passwordFields = document.querySelectorAll('input[type="password"]');
        if (passwordFields.length > 0) {
          passwordFields.forEach(field => {
            const form = field.closest('form');
            if (form) {
              // Check for CSRF protection
              const csrfToken = form.querySelector('input[name*="csrf"], input[name*="token"], input[name="_token"], meta[name="csrf-token"]');
              if (!csrfToken) {
                this.addVulnerability({
                  type: 'MISSING_CSRF_PROTECTION',
                  severity: 'high',
                  title: 'Login form missing CSRF protection',
                  description: 'No CSRF token found in login form',
                  recommendation: 'Implement CSRF protection tokens'
                });
                return; // Only report once
              }
            }
          });
        }
        
        // Check for JWT in localStorage (simplified)
        try {
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);
            
            if (value && typeof value === 'string' && value.match(/^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/)) {
              this.addVulnerability({
                type: 'JWT_IN_LOCALSTORAGE',
                severity: 'high',
                title: 'JWT token stored in localStorage',
                description: 'JWT tokens accessible via JavaScript',
                recommendation: 'Store JWT tokens in httpOnly cookies',
                evidence: `Key: ${key}`
              });
              return; // Only report once
            }
          }
        } catch (e) {
          // localStorage not accessible
        }
      } catch (error) {
        console.error('Content: Error in auth check:', error);
      }
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
    
    // Simplified version of checkHTTPS
    checkHTTPS() {
      try {
        if (window.location.protocol !== 'https:') {
          this.addVulnerability({
            type: 'NO_HTTPS',
            severity: 'critical', // Changed from 'high' to 'critical'
            title: 'Site not using HTTPS',
            description: 'Data transmitted without encryption',
            recommendation: 'Implement HTTPS certificate and redirect all HTTP traffic to HTTPS',
            evidence: `Current protocol: ${window.location.protocol}`
          });
        } else {
          this.addVulnerability({
            type: 'HTTPS_VERIFIED',
            severity: 'info',
            title: 'HTTPS properly implemented',
            description: 'Site correctly uses HTTPS encryption',
            recommendation: 'Continue monitoring certificate validity',
            evidence: `Protocol: ${window.location.protocol}`
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
              evidence: `Form action: ${form.action}`
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
              evidence: `${passwordFields.length} password field(s) found`
            });
            return; // Only report once
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
              evidence: `${httpScripts.length} insecure script(s)`
            });
          }
          
          const httpImages = document.querySelectorAll('img[src^="http://"]');
          if (httpImages.length > 0) {
            this.addVulnerability({
              type: 'MIXED_CONTENT_IMAGES',
              severity: 'low',
              title: 'Images loaded via HTTP',
              description: 'Images can be intercepted',
              recommendation: 'Load images via HTTPS',
              evidence: `${httpImages.length} insecure image(s)`
            });
          }
        }
      } catch (error) {
        console.error('Content: Error in mixed content check:', error);
      }
    }
    
    checkOutdatedLibraries() {
      try {
        // Check jQuery (Fixed)
        if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) {
          const version = window.jQuery.fn.jquery;
          const versionParts = version.split('.');
          const majorVersion = parseInt(versionParts[0]) || 0;
          const minorVersion = parseInt(versionParts[1]) || 0;
          
          if (majorVersion < 3 || (majorVersion === 3 && minorVersion < 5)) {
            this.addVulnerability({
              type: 'OUTDATED_JQUERY',
              severity: 'medium',
              title: 'Outdated jQuery version',
              description: 'Old version may contain known vulnerabilities',
              recommendation: 'Update to jQuery 3.5 or later',
              evidence: `Current version: ${version}`
            });
          }
        }
        
        // Check for other frameworks
        // Angular.js (legacy)
        if (window.angular && window.angular.version) {
          const version = window.angular.version.full;
          if (version.startsWith('1.')) {
            this.addVulnerability({
              type: 'OUTDATED_ANGULAR',
              severity: 'medium',
              title: 'Legacy AngularJS detected',
              description: 'AngularJS (1.x) is no longer supported',
              recommendation: 'Migrate to modern Angular or another framework',
              evidence: `Version: ${version}`
            });
          }
        }
        
      } catch (error) {
        console.error('Content: Error in library check:', error);
      }
    }
    
    checkCSP() {
      try {
        const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        
        if (!cspMeta) {
          this.addVulnerability({
            type: 'NO_CSP',
            severity: 'medium',
            title: 'No Content Security Policy',
            description: 'Site vulnerable to script injection (XSS)',
            recommendation: 'Implement CSP to prevent XSS'
          });
        } else {
          // Advanced CSP analysis
          const cspContent = cspMeta.content;
          
          if (cspContent.includes('unsafe-inline')) {
            this.addVulnerability({
              type: 'CSP_UNSAFE_INLINE',
              severity: 'medium',
              title: 'CSP allows unsafe-inline',
              description: 'Content Security Policy permits inline scripts, reducing XSS protection',
              recommendation: 'Remove unsafe-inline and use nonces or hashes for inline scripts',
              evidence: 'unsafe-inline directive found'
            });
          }
          
          if (cspContent.includes('unsafe-eval')) {
            this.addVulnerability({
              type: 'CSP_UNSAFE_EVAL',
              severity: 'medium',
              title: 'CSP allows unsafe-eval',
              description: 'Content Security Policy permits eval(), reducing security',
              recommendation: 'Remove unsafe-eval and refactor code to avoid eval()',
              evidence: 'unsafe-eval directive found'
            });
          }
          
          if (cspContent.includes('*') && !cspContent.includes('*.')) {
            this.addVulnerability({
              type: 'CSP_WILDCARD',
              severity: 'high',
              title: 'CSP uses wildcard source',
              description: 'Content Security Policy allows scripts from any source',
              recommendation: 'Specify exact trusted sources instead of wildcards',
              evidence: 'Wildcard (*) source found'
            });
          }
        }
      } catch (error) {
        console.error('Content: Error in CSP check:', error);
      }
    }
    
    checkExternalLinks() {
      try {
        const links = document.querySelectorAll('a[href]');
        let insecureLinks = 0;
        
        links.forEach(link => {
          if (link.target === '_blank' && !link.rel?.includes('noopener')) {
            insecureLinks++;
          }
        });
        
        if (insecureLinks > 0) {
          this.addVulnerability({
            type: 'TABNABBING',
            severity: 'low',
            title: 'Links vulnerable to tabnabbing',
            description: 'External links can control the original page',
            recommendation: 'Add rel="noopener noreferrer" to target="_blank" links',
            evidence: `${insecureLinks} vulnerable link(s)`
          });
        }
      } catch (error) {
        console.error('Content: Error in links check:', error);
      }
    }
    
    // Comprehensive SQL Injection Detection
    checkSQLInjection() {
      console.log('Content: Starting SQL injection analysis...');
      
      try {
        // 1. Check URL parameters for SQL injection patterns
        this.checkURLParametersForSQL();
        
        // 2. Check forms for SQL injection risks
        this.checkFormsForSQL();
        
        // 3. Check for SQL error messages in page content
        this.checkSQLErrorMessages();
        
        // 4. Check JavaScript for SQL patterns
        this.checkJavaScriptForSQL();
        
        // 5. Check for database references
        this.checkDatabaseReferences();
        
        console.log('Content: SQL injection analysis completed');
        
      } catch (error) {
        console.error('Content: Error in SQL injection check:', error);
      }
    }
    
    // Check URL parameters for SQL injection patterns (Enhanced)
    checkURLParametersForSQL() {
      try {
        const urlParams = new URLSearchParams(window.location.search);
        
        // Enhanced patterns for balanced detection
        const sqlPatterns = SCANNER_CONFIG.DETECTION_MODE === 'paranoid' ? [
          // Paranoid mode - more aggressive
          /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/i,
          /(\b(or|and)\s+\d+\s*=\s*\d+)/i,
          /(\b(or|and)\s+['"]\w+['"]?\s*=\s*['"]\w+['"]?)/i,
          /(--|\#|\/\*|\*\/)/,
          /(\b(xp_|sp_)\w+)/i,
          /(\b(char|varchar|nchar|nvarchar)\s*\(\s*\d+\s*\))/i,
          /(\b(waitfor|delay)\b)/i,
          /(benchmark\s*\(\s*\d+)/i,
          /(\bsleep\s*\(\s*\d+\s*\))/i,
          /(\bunion\s+all\s+select)/i,
          /(\border\s+by\s+\d+)/i,
          /(\bhaving\s+\d+\s*=\s*\d+)/i
        ] : [
          // Balanced mode - avoid false positives
          /(\b(union\s+select|union\s+all\s+select)\b)/i,
          /(\b(or|and)\s+\d+\s*=\s*\d+\s*(--|\#))/i,
          /(';|";)\s*(drop|delete|update)\s+/i,
          /(\bexec\s*\(\s*xp_)/i,
          /(\bwaitfor\s+delay\s+)/i,
          /(benchmark\s*\(\s*\d+.*,.*\))/i,
          /(\bsleep\s*\(\s*\d+\s*\)\s*(--|\#))/i
        ];
        
        urlParams.forEach((value, key) => {
          // Skip common false positive parameters
          if (['action', 'select', 'order', 'sort', 'filter'].includes(key.toLowerCase()) && 
              value.length < 20 && !/['"`;]/.test(value)) {
            return; // Skip likely legitimate parameters
          }
          
          // Check for SQL injection patterns
          sqlPatterns.forEach((pattern) => {
            if (pattern.test(value)) {
              this.addVulnerability({
                type: 'SQL_INJECTION_URL_PARAMS',
                severity: 'critical', // Changed from 'high' to 'critical'
                title: 'SQL Injection Pattern in URL Parameter',
                description: `URL parameter "${key}" contains potential SQL injection pattern`,
                recommendation: 'Use parameterized queries and input validation',
                evidence: `Parameter: ${key}=${value.substring(0, 100)}${value.length > 100 ? '...' : ''}`
              });
            }
          });
          
          // Check for numeric injection attempts
          if (/^\d+['";]/.test(value) || /['";]\d+$/.test(value)) {
            this.addVulnerability({
              type: 'SQL_INJECTION_URL_PARAMS',
              severity: 'high', // Keep as high for numeric attempts
              title: 'Potential SQL Injection in Numeric Parameter',
              description: `URL parameter "${key}" contains suspicious numeric patterns`,
              recommendation: 'Validate and sanitize numeric inputs',
              evidence: `Parameter: ${key}=${value}`
            });
          }
        });
      } catch (error) {
        console.error('Content: Error checking URL parameters for SQL:', error);
      }
    }
    
    // Check forms for SQL injection risks
    checkFormsForSQL() {
      try {
        const forms = document.querySelectorAll('form');
        
        forms.forEach((form, formIndex) => {
          const inputs = form.querySelectorAll('input, textarea, select');
          let riskLevel = 'low';
          let riskyInputs = [];
          
          inputs.forEach(input => {
            const name = input.name || input.id || `input-${formIndex}`;
            const type = input.type || 'text';
            
            // Higher risk inputs
            if (['search', 'text', 'email', 'url'].includes(type) || input.tagName === 'TEXTAREA') {
              riskyInputs.push(name);
              
              // Check for database-related names
              if (/\b(id|user|name|email|search|query|sql|db)\b/i.test(name)) {
                riskLevel = 'medium';
              }
              
              // Check for suspicious placeholder or value patterns
              const placeholder = input.placeholder || '';
              const value = input.value || '';
              
              if (/\b(select|from|where|order|group)\b/i.test(placeholder + ' ' + value)) {
                riskLevel = 'high';
              }
            }
          });
          
          if (riskyInputs.length > 0) {
            const severity = riskLevel === 'high' ? 'high' : riskLevel === 'medium' ? 'medium' : 'low';
            
            this.addVulnerability({
              type: `SQL_INJECTION_FORM_${riskLevel.toUpperCase()}_RISK`,
              severity: severity,
              title: `Form with SQL Injection Risk (${riskLevel})`,
              description: `Form contains ${riskyInputs.length} input field(s) that could be vulnerable to SQL injection`,
              recommendation: 'Implement server-side validation, parameterized queries, and input sanitization',
              evidence: `Risky inputs: ${riskyInputs.join(', ')}`
            });
          }
        });
      } catch (error) {
        console.error('Content: Error checking forms for SQL:', error);
      }
    }
    
    // Check for SQL error messages in page content
    checkSQLErrorMessages() {
      try {
        const pageText = document.body ? document.body.innerText : '';
        const sqlErrors = [
          // MySQL errors
          /You have an error in your SQL syntax/i,
          /MySQL server version for the right syntax/i,
          /mysql_fetch_array\(\)/i,
          /mysql_fetch_assoc\(\)/i,
          /mysql_num_rows\(\)/i,
          /Duplicate entry .* for key/i,
          
          // PostgreSQL errors
          /PostgreSQL query failed/i,
          /pg_query\(\)/i,
          /pg_exec\(\)/i,
          /supplied argument is not a valid PostgreSQL result/i,
          
          // Microsoft SQL Server errors
          /Microsoft OLE DB Provider for ODBC Drivers/i,
          /Microsoft OLE DB Provider for SQL Server/i,
          /Unclosed quotation mark after the character string/i,
          /Invalid column name/i,
          /Incorrect syntax near/i,
          /Conversion failed when converting/i,
          
          // Oracle errors
          /ORA-\d{5}/,
          /Oracle error/i,
          /OCI.dll/i,
          
          // SQLite errors
          /SQLite error/i,
          /sqlite3_step/i,
          /no such table/i,
          
          // Generic SQL errors
          /SQL syntax.*MySQL/i,
          /Warning.*mysql_.*\(\)/i,
          /valid MySQL result/i,
          /MySqlClient\./i,
          /System\.Data\.SqlClient\./i
        ];
        
        sqlErrors.forEach((pattern) => {
          if (pattern.test(pageText)) {
            this.addVulnerability({
              type: 'SQL_ERROR_MESSAGES',
              severity: 'critical',
              title: 'SQL Database Error Messages Exposed',
              description: 'Page contains SQL database error messages that reveal system information',
              recommendation: 'Configure proper error handling to hide database errors from users',
              evidence: 'SQL error patterns detected in page content'
            });
            return; // Only report once
          }
        });
      } catch (error) {
        console.error('Content: Error checking SQL error messages:', error);
      }
    }
    
    // Check JavaScript for SQL patterns
    checkJavaScriptForSQL() {
      try {
        const scripts = document.querySelectorAll('script');
        let sqlInJS = false;
        let evidenceCount = 0;
        
        scripts.forEach(script => {
          const scriptContent = script.textContent || script.innerHTML || '';
          
          // Patterns that suggest SQL in JavaScript
          const sqlPatterns = [
            /["'`]\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\s+/i,
            /query\s*[:=]\s*["'`][^"'`]*\b(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE)\b/i,
            /sql\s*[:=]\s*["'`]/i,
            /execute\s*\(\s*["'`][^"'`]*\b(SELECT|INSERT|UPDATE|DELETE)\b/i,
            /\b(mysql_query|pg_query|sqlite_exec)\s*\(/i,
            /\bexecute\s*\(\s*["'`].*\+.*["'`]\s*\)/i,
            /["'`]\s*\+\s*\w+\s*\+\s*["'`].*\b(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE)\b/i
          ];
          
          sqlPatterns.forEach(pattern => {
            if (pattern.test(scriptContent)) {
              sqlInJS = true;
              evidenceCount++;
            }
          });
        });
        
        if (sqlInJS) {
          this.addVulnerability({
            type: 'SQL_IN_JAVASCRIPT',
            severity: 'high', // Changed from 'medium' to 'high'
            title: 'SQL Queries in JavaScript Code',
            description: 'JavaScript code contains SQL query patterns which may indicate client-side SQL construction',
            recommendation: 'Move SQL queries to server-side code and use parameterized queries',
            evidence: `${evidenceCount} SQL pattern(s) found in JavaScript`
          });
        }
        
        // Check for specific dangerous patterns
        const dangerousPatterns = [
          /eval\s*\(\s*["'`][^"'`]*\b(SELECT|INSERT|UPDATE|DELETE)\b/i,
          /new\s+Function\s*\([^)]*\b(SELECT|INSERT|UPDATE|DELETE)\b/i
        ];
        
        scripts.forEach(script => {
          const scriptContent = script.textContent || script.innerHTML || '';
          
          dangerousPatterns.forEach(pattern => {
            if (pattern.test(scriptContent)) {
              this.addVulnerability({
                type: 'SQL_INJECTION_DYNAMIC_EXECUTION',
                severity: 'critical',
                title: 'Dynamic SQL Execution in JavaScript',
                description: 'JavaScript uses eval() or Function() with SQL patterns',
                recommendation: 'Remove dynamic code execution with SQL patterns',
                evidence: 'Dynamic SQL execution detected'
              });
              return; // Only report once
            }
          });
        });
        
      } catch (error) {
        console.error('Content: Error checking JavaScript for SQL:', error);
      }
    }
    
    // Check for database references and exposure
    checkDatabaseReferences() {
      try {
        const pageText = document.body ? document.body.innerText.toLowerCase() : '';
        const pageHTML = document.body ? document.body.innerHTML.toLowerCase() : '';
        
        // Database connection strings
        const connectionPatterns = [
          /server\s*=.*database\s*=/i,
          /data\s+source\s*=.*initial\s+catalog\s*=/i,
          /mongodb:\/\//i,
          /mysql:\/\//i,
          /postgresql:\/\//i,
          /jdbc:[^;]+/i,
          /provider\s*=\s*[^;]*(oledb|sqloledb)/i
        ];
        
        connectionPatterns.forEach(pattern => {
          if (pattern.test(pageHTML)) {
            this.addVulnerability({
              type: 'DATABASE_CONNECTION_EXPOSED',
              severity: 'critical',
              title: 'Database Connection String Exposed',
              description: 'Database connection information is visible in page source',
              recommendation: 'Remove database connection strings from client-side code',
              evidence: 'Database connection pattern detected'
            });
            return; // Only report once
          }
        });
        
        // Database technology references
        const dbReferences = [
          { pattern: /\bmysql\b/i, name: 'MySQL' },
          { pattern: /\bpostgresql\b|\bpostgres\b/i, name: 'PostgreSQL' },
          { pattern: /\bsqlserver\b|\bmssql\b/i, name: 'SQL Server' },
          { pattern: /\boracle\b.*\bdatabase\b/i, name: 'Oracle' },
          { pattern: /\bmongodb\b|\bmongo\b/i, name: 'MongoDB' },
          { pattern: /\bsqlite\b/i, name: 'SQLite' },
          { pattern: /\bredis\b/i, name: 'Redis' },
          { pattern: /\bcassandra\b/i, name: 'Cassandra' }
        ];
        
        let detectedDatabases = [];
        dbReferences.forEach(db => {
          if (db.pattern.test(pageText) || db.pattern.test(pageHTML)) {
            detectedDatabases.push(db.name);
          }
        });
        
        if (detectedDatabases.length > 0) {
          this.addVulnerability({
            type: 'DATABASE_REFERENCES_DETECTED',
            severity: 'info',
            title: 'Database Technology References Found',
            description: `Page contains references to database technologies: ${detectedDatabases.join(', ')}`,
            recommendation: 'Consider if database technology should be exposed to clients',
            evidence: `Detected: ${detectedDatabases.join(', ')}`
          });
        }
        
        // Check for database table/column naming patterns
        const tablePatterns = [
          /\b(users?|accounts?|customers?|orders?|products?|admins?)\s+(table|tbl)/i,
          /\b(user_id|customer_id|order_id|product_id|admin_id)\b/i,
          /\b(username|password|email|user_name|pass_word)\s+(column|field)/i
        ];
        
        let foundPattern = false;
        tablePatterns.forEach(pattern => {
          if (pattern.test(pageText) && !foundPattern) {
            this.addVulnerability({
              type: 'DATABASE_SCHEMA_EXPOSED',
              severity: 'medium',
              title: 'Database Schema Information Exposed',
              description: 'Page content reveals database table or column information',
              recommendation: 'Remove database schema references from public content',
              evidence: 'Database schema patterns detected'
            });
            foundPattern = true;
          }
        });
        
      } catch (error) {
        console.error('Content: Error checking database references:', error);
      }
    }
    
    // COOKIE SECURITY SCANNER
    checkCookieSecurity() {
      try {
        console.log('Content: Starting cookie security analysis...');
        
        // Get all cookies accessible via JavaScript
        const cookies = document.cookie;
        if (cookies) {
          // Parse cookies
          const cookieList = cookies.split(';').map(c => c.trim());
          const jsAccessibleCookies = cookieList.filter(c => c.length > 0);
          
          if (jsAccessibleCookies.length > 0) {
            this.addVulnerability({
              type: 'COOKIES_NOT_HTTPONLY',
              severity: 'medium',
              title: 'Cookies accessible via JavaScript',
              description: `${jsAccessibleCookies.length} cookie(s) can be accessed by JavaScript, vulnerable to XSS theft`,
              recommendation: 'Set HttpOnly flag on all session cookies',
              evidence: `Accessible cookies: ${jsAccessibleCookies.length}`
            });
          }
        }
        
        // Check for secure flag on HTTPS sites
        if (window.location.protocol === 'https:' && cookies) {
          this.addVulnerability({
            type: 'COOKIES_SECURE_FLAG_CHECK',
            severity: 'info',
            title: 'Cookie security flags should be verified',
            description: 'Ensure all cookies have Secure flag set for HTTPS sites',
            recommendation: 'Use browser DevTools to verify Secure and SameSite flags'
          });
        }
        
      } catch (error) {
        console.error('Content: Error in cookie check:', error);
      }
    }
    
    // API AND CORS SCANNER
    checkAPIsAndCORS() {
      try {
        console.log('Content: Starting API and CORS analysis...');
        
        // Check for external resources
        const scripts = document.querySelectorAll('script[src]');
        const stylesheets = document.querySelectorAll('link[rel="stylesheet"]');
        const images = document.querySelectorAll('img[src]');
        
        const apis = new Set();
        let externalResources = 0;
        
        [...scripts, ...stylesheets, ...images].forEach(element => {
          const src = element.src || element.href;
          if (src) {
            try {
              const url = new URL(src);
              if (url.origin !== window.location.origin) {
                externalResources++;
                apis.add(url.origin);
              }
            } catch (e) {
              // Invalid URL, skip
            }
          }
        });
        
        if (externalResources > 0) {
          this.addVulnerability({
            type: 'EXTERNAL_RESOURCES',
            severity: 'info',
            title: 'External resources detected',
            description: `Page loads ${externalResources} resources from external domains`,
            recommendation: 'Verify all external domains are trusted and use SRI for scripts',
            evidence: `External origins: ${[...apis].slice(0, 5).join(', ')}${apis.size > 5 ? '...' : ''}`
          });
        }
        
      } catch (error) {
        console.error('Content: Error in API/CORS check:', error);
      }
    }
    
    // SUBRESOURCE INTEGRITY (SRI) CHECKER
    checkSubresourceIntegrity() {
      try {
        console.log('Content: Checking Subresource Integrity...');
        
        const externalScripts = document.querySelectorAll('script[src]');
        const externalStyles = document.querySelectorAll('link[rel="stylesheet"][href]');
        
        let scriptsWithoutSRI = 0;
        let stylesWithoutSRI = 0;
        
        externalScripts.forEach(script => {
          if (script.src) {
            try {
              const url = new URL(script.src);
              if (url.origin !== window.location.origin && !script.integrity) {
                scriptsWithoutSRI++;
              }
            } catch (e) {
              // Invalid URL, skip
            }
          }
        });
        
        externalStyles.forEach(style => {
          if (style.href) {
            try {
              const url = new URL(style.href);
              if (url.origin !== window.location.origin && !style.integrity) {
                stylesWithoutSRI++;
              }
            } catch (e) {
              // Invalid URL, skip
            }
          }
        });
        
        if (scriptsWithoutSRI > 0) {
          this.addVulnerability({
            type: 'MISSING_SRI_SCRIPTS',
            severity: 'medium',
            title: 'External scripts without integrity checks',
            description: `${scriptsWithoutSRI} external script(s) loaded without Subresource Integrity`,
            recommendation: 'Add integrity attribute to all external scripts',
            evidence: `Scripts without SRI: ${scriptsWithoutSRI}`
          });
        }
        
        if (stylesWithoutSRI > 0) {
          this.addVulnerability({
            type: 'MISSING_SRI_STYLES',
            severity: 'low',
            title: 'External stylesheets without integrity checks',
            description: `${stylesWithoutSRI} external stylesheet(s) loaded without Subresource Integrity`,
            recommendation: 'Add integrity attribute to all external stylesheets',
            evidence: `Stylesheets without SRI: ${stylesWithoutSRI}`
          });
        }
        
      } catch (error) {
        console.error('Content: Error in SRI check:', error);
      }
    }
    
    // SENSITIVE INFORMATION DETECTOR WITH REGIONAL COMPLIANCE
    checkSensitiveInformation() {
      try {
        console.log('Content: Scanning for sensitive information with regional compliance...');
        
        const pageText = document.body ? document.body.innerText : '';
        const pageHTML = document.body ? document.body.innerHTML : '';
        
        // Initialize Regional Compliance Detector
        const userLocale = navigator.language || 'en-US';
        let regions = ['ALL']; // Default to all regions
        
        // Customize based on locale
        if (userLocale.startsWith('pt-BR')) {
          regions = ['BR', 'US', 'EU'];
        } else if (userLocale.startsWith('en-US')) {
          regions = ['US', 'CA', 'UK', 'AU'];
        } else if (userLocale.startsWith('es')) {
          regions = ['MX', 'EU', 'US'];
        } else if (userLocale.includes('fr')) {
          regions = ['EU', 'CA'];
        } else if (userLocale.includes('de')) {
          regions = ['EU'];
        } else if (userLocale.includes('it')) {
          regions = ['EU'];
        } else if (userLocale.includes('ja')) {
          regions = ['JP'];
        } else if (userLocale.includes('ko')) {
          regions = ['KR'];
        } else if (userLocale.includes('hi') || userLocale.includes('in')) {
          regions = ['IN'];
        }
        
        console.log(`Content: Using regional compliance for regions: ${regions.join(', ')}`);
        
        const detector = new RegionalComplianceDetector(regions);
        
        // Detect regional identifiers
        const detections = detector.detectIdentifiers(pageText);
        
        // Generate vulnerabilities
        const regionalVulnerabilities = detector.generateVulnerabilities();
        
        // Add regional vulnerabilities
        regionalVulnerabilities.forEach(vuln => {
          this.addVulnerability(vuln);
        });
        
        // Get compliance summary for logging
        const summary = detector.getComplianceSummary();
        if (summary.totalIdentifiersFound > 0) {
          console.log('Regional Compliance Summary:', summary);
          
          // Add a summary vulnerability if multiple regions affected
          if (Object.keys(summary.byRegion).length > 1) {
            this.addVulnerability({
              type: 'MULTI_REGION_COMPLIANCE_RISK',
              severity: 'high',
              title: 'Multiple Regional Compliance Violations',
              description: `Personal identifiers from ${Object.keys(summary.byRegion).length} different regions detected`,
              recommendation: `Review compliance with: ${summary.laws.join(', ')}`,
              evidence: `Regions affected: ${Object.keys(summary.byRegion).join(', ')}`
            });
          }
        }
        
        // Continue with other sensitive data patterns
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
          {
            name: 'API key',
            pattern: /\b(api[_-]?key|apikey|api_token|access[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
            severity: 'critical',
            type: 'EXPOSED_API_KEY'
          },
          {
            name: 'Private key',
            pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g,
            severity: 'critical',
            type: 'EXPOSED_PRIVATE_KEY'
          },
          {
            name: 'AWS access key',
            pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
            severity: 'critical',
            type: 'EXPOSED_AWS_KEY'
          },
          {
            name: 'Email addresses',
            pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
            severity: 'info',
            type: 'EXPOSED_EMAIL',
            maxAllowed: 10
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
            this.addVulnerability({
              type: type,
              severity: severity,
              title: `${name} exposed in page content`,
              description: `Found ${validMatches.length} instance(s) of ${name.toLowerCase()} in page content`,
              recommendation: `Remove ${name.toLowerCase()} from client-side code and use server-side storage`,
              evidence: severity === 'critical' ? 'Pattern detected (content hidden for security)' : 
                       `Found ${validMatches.length} instance(s)`
            });
          }
        });
        
        // Check localStorage and sessionStorage
        this.checkStorageForSensitiveData();
        
      } catch (error) {
        console.error('Content: Error checking sensitive information:', error);
      }
    }
    
    addVulnerability(vuln) {
      try {
        vuln.timestamp = Date.now();
        vuln.url = window.location.href;
        
        // Normalize severity
        vuln.severity = (vuln.severity || 'info').toLowerCase();
        
        // Check for duplicates based on type and title
        const isDuplicate = this.vulnerabilities.some(existing => {
          return existing.type === vuln.type && existing.title === vuln.title;
        });
        
        if (!isDuplicate) {
          this.vulnerabilities.push(vuln);
          console.log(`🚨 Vulnerability detected: ${vuln.title} [${vuln.severity}]`);
        }
      } catch (error) {
        console.error('Content: Error adding vulnerability:', error);
      }
    }
    
    sendResults() {
      try {
        // Simple deduplication
        const uniqueVulnerabilities = this.vulnerabilities.filter((vuln, index, self) => 
          index === self.findIndex(v => v.type === vuln.type && v.title === vuln.title)
        );
        
        const score = this.calculateSecurityScore(uniqueVulnerabilities);
        
        const results = {
          type: 'SCAN_COMPLETE',
          url: window.location.href,
          vulnerabilities: uniqueVulnerabilities,
          score: score,
          timestamp: Date.now()
        };
        
        console.log(`Content: Sending ${uniqueVulnerabilities.length} vulnerabilities with score ${score}`);
        console.log('Content: Results:', results);
        
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
                setTimeout(trySend, 500 * attempts); // Increasing delay
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
          score -= penalties[severity] || 5;
        }
      });
      
      return Math.max(0, score);
    }
  }
  
  // Force start the scanner
  console.log('Content: Creating scanner instance...');
  try {
    const scanner = new VulnerabilityScanner();
    window.navSecScanner = scanner; // For debugging
    console.log('Content: ✅ Scanner v1.1 created and started');
  } catch (error) {
    console.error('Content: ❌ Failed to create scanner:', error);
  }
  
})();