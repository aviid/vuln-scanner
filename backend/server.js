const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fileUpload = require('express-fileupload');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Increase payload limit for JSON requests
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(fileUpload({
  createParentPath: true,
  limits: { fileSize: 10 * 1024 * 1024 },
}));

const API_KEYS = {
  nvd: process.env.NVD_API_KEY || '',
  snyk: process.env.SNYK_API_TOKEN || '',
  ossIndex: process.env.OSS_INDEX_API_KEY || ''
};

// Store scan results in memory (in production, use a database)
const scanResultsStore = new Map();

function parseDependencies(fileContent, fileType) {
  const dependencies = [];
  
  try {
    switch (fileType) {
      case 'package.json':
        const packageJson = JSON.parse(fileContent);
        const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };
        for (const [name, version] of Object.entries(deps)) {
          dependencies.push({
            name,
            version: version.replace(/^[\^~]/, ''),
            type: 'npm'
          });
        }
        break;
        
      case 'composer.json':
        const composerJson = JSON.parse(fileContent);
        const composerDeps = { ...composerJson.require, ...composerJson['require-dev'] };
        for (const [name, version] of Object.entries(composerDeps)) {
          if (!name.includes('/')) continue;
          dependencies.push({
            name,
            version: version.replace(/^[\^~]/, ''),
            type: 'composer'
          });
        }
        break;
        
      case 'requirements.txt':
        const lines = fileContent.split('\n');
        lines.forEach(line => {
          line = line.trim();
          if (line && !line.startsWith('#') && !line.startsWith('-')) {
            const match = line.match(/^([a-zA-Z0-9._-]+)([=<>!]=?.*)?$/);
            if (match) {
              dependencies.push({
                name: match[1],
                version: match[2] ? match[2].replace(/^=/, '') : '*',
                type: 'python'
              });
            }
          }
        });
        break;
    }
  } catch (error) {
    console.error('Error parsing dependencies:', error);
  }
  
  return dependencies;
}

async function checkNVD(dependency) {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0`;
    const params = {
      keywordSearch: dependency.name,
      resultsPerPage: 10 // Reduced for demo
    };
    
    const headers = {};
    if (API_KEYS.nvd) {
      headers['apiKey'] = API_KEYS.nvd;
    }
    
    const response = await axios.get(url, { params, headers });
    const vulnerabilities = [];
    
    if (response.data.vulnerabilities) {
      response.data.vulnerabilities.forEach(vuln => {
        const cve = vuln.cve;
        // Only include relevant vulnerabilities
        if (cve.descriptions && cve.descriptions[0]) {
          vulnerabilities.push({
            id: cve.id,
            description: cve.descriptions[0].value.substring(0, 200), // Limit description length
            severity: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 
                     cve.metrics?.cvssMetricV2?.[0]?.baseSeverity || 'UNKNOWN',
            score: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                  cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || 0,
            references: cve.references?.slice(0, 2).map(ref => ref.url) || [], // Limit references
            published: cve.published
          });
        }
      });
    }
    
    return vulnerabilities.slice(0, 5); // Limit to 5 vulnerabilities per dependency
  } catch (error) {
    console.error('NVD API error:', error.response?.data || error.message);
    return [];
  }
}

async function checkSnyk(dependency) {
  if (!API_KEYS.snyk) return [];
  
  try {
    const url = `https://api.snyk.io/rest/orgs/${process.env.SNYK_ORG_ID}/packages/${dependency.name}/issues`;
    const headers = {
      'Authorization': `token ${API_KEYS.snyk}`,
      'Content-Type': 'application/vnd.api+json'
    };
    
    const response = await axios.get(url, { headers });
    return (response.data.data || []).slice(0, 3); // Limit Snyk results
  } catch (error) {
    console.error('Snyk API error:', error.response?.data || error.message);
    return [];
  }
}

async function checkOSSIndex(dependency) {
  try {
    const url = 'https://ossindex.sonatype.org/api/v3/component-report';
    const headers = {
      'Content-Type': 'application/json'
    };
    
    if (API_KEYS.ossIndex) {
      headers['Authorization'] = `Basic ${Buffer.from(API_KEYS.ossIndex).toString('base64')}`;
    }
    
    const coordinates = `${dependency.type}:${dependency.name}:${dependency.version}`;
    const response = await axios.post(url, { coordinates }, { headers });
    
    return (response.data.vulnerabilities || []).slice(0, 3); // Limit OSS results
  } catch (error) {
    console.error('OSS Index API error:', error.response?.data || error.message);
    return [];
  }
}

app.post('/api/scan', async (req, res) => {
  try {
    if (!req.files || !req.files.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const file = req.files.file;
    const fileType = req.body.fileType;
    const fileContent = file.data.toString('utf8');
    
    const dependencies = parseDependencies(fileContent, fileType);
    const results = [];
    
    // Limit the number of dependencies scanned for demo
    const limitedDependencies = dependencies.slice(0, 20);
    
    for (const dependency of limitedDependencies) {
      console.log(`Scanning: ${dependency.name}@${dependency.version}`);
      
      const [nvdVulns, snykVulns, ossVulns] = await Promise.all([
        checkNVD(dependency),
        checkSnyk(dependency),
        checkOSSIndex(dependency)
      ]);
      
      const allVulnerabilities = [...nvdVulns, ...snykVulns, ...ossVulns];
      
      if (allVulnerabilities.length > 0) {
        results.push({
          dependency: dependency.name,
          version: dependency.version,
          type: dependency.type,
          vulnerabilities: allVulnerabilities
        });
      }
    }
    
    const scanId = Date.now().toString();
    const scanResult = {
      scanId: scanId,
      timestamp: new Date().toISOString(),
      totalDependencies: dependencies.length,
      scannedDependencies: limitedDependencies.length,
      vulnerableDependencies: results.length,
      results: results
    };
    
    // Store results with scanId as key
    scanResultsStore.set(scanId, scanResult);
    
    res.json(scanResult);
    
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: 'Internal server error during scanning' });
  }
});

// New endpoint to generate PDF by scanId (avoids sending large data)
app.get('/api/generate-pdf/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const scanResults = scanResultsStore.get(scanId);
    
    if (!scanResults) {
      return res.status(404).json({ error: 'Scan results not found' });
    }

    const doc = new PDFDocument();
    const filename = `vulnerability-report-${scanId}.pdf`;
    
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/pdf');
    
    doc.pipe(res);
    
    // Title
    doc.fontSize(20).text('Vulnerability Scan Report', 100, 100);
    doc.fontSize(12).text(`Generated on: ${new Date(scanResults.timestamp).toLocaleString()}`, 100, 130);
    doc.text(`Scan ID: ${scanId}`, 100, 150);
    doc.moveDown(2);
    
    // Summary
    doc.fontSize(16).text('Scan Summary', 100, doc.y);
    doc.fontSize(10);
    doc.text(`Total Dependencies: ${scanResults.totalDependencies}`);
    doc.text(`Dependencies Scanned: ${scanResults.scannedDependencies}`);
    doc.text(`Vulnerable Dependencies Found: ${scanResults.vulnerableDependencies}`);
    doc.moveDown();
    
    // Vulnerabilities
    if (scanResults.results && scanResults.results.length > 0) {
      doc.fontSize(16).text('Vulnerabilities Found:', 100, doc.y);
      doc.moveDown();
      
      scanResults.results.forEach((result, index) => {
        // Add new page if needed
        if (doc.y > 650) {
          doc.addPage();
          doc.fontSize(12);
        }
        
        doc.fontSize(12).text(`${index + 1}. ${result.dependency}@${result.version} (${result.type})`, { underline: true });
        doc.moveDown(0.3);
        
        result.vulnerabilities.forEach((vuln, vulnIndex) => {
          if (doc.y > 700) {
            doc.addPage();
            doc.fontSize(10);
          }
          
          doc.fontSize(10);
          doc.text(`   ${vulnIndex + 1}. ${vuln.id}`, { continued: true });
          doc.text(` - Severity: ${vuln.severity}`, { continued: true });
          doc.text(` - Score: ${vuln.score}`);
          doc.text(`   Description: ${vuln.description}`);
          doc.moveDown(0.2);
        });
        
        doc.moveDown(0.5);
      });
    } else {
      doc.text('No vulnerabilities found!', 100, doc.y);
    }
    
    // Clean up stored results after PDF generation
    setTimeout(() => {
      scanResultsStore.delete(scanId);
    }, 30000); // Clean up after 30 seconds
    
    doc.end();
    
  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({ error: 'Failed to generate PDF' });
  }
});

// Keep the old endpoint for backward compatibility (with limits)
app.post('/api/generate-pdf', async (req, res) => {
  try {
    const { scanResults, title = 'Vulnerability Scan Report' } = req.body;
    
    // Validate and limit data
    if (!scanResults || !scanResults.results) {
      return res.status(400).json({ error: 'Invalid scan results' });
    }
    
    // Limit the data for PDF generation
    const limitedResults = {
      ...scanResults,
      results: scanResults.results.slice(0, 10).map(result => ({
        ...result,
        vulnerabilities: result.vulnerabilities.slice(0, 5)
      }))
    };
    
    const doc = new PDFDocument();
    const filename = `vulnerability-report-${Date.now()}.pdf`;
    
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/pdf');
    
    doc.pipe(res);
    
    doc.fontSize(20).text(title, 100, 100);
    doc.fontSize(12).text(`Generated on: ${new Date().toLocaleString()}`, 100, 130);
    doc.moveDown(2);
    
    doc.fontSize(16).text('Scan Summary', 100, doc.y);
    doc.fontSize(10);
    doc.text(`Total Dependencies Scanned: ${limitedResults.totalDependencies}`);
    doc.text(`Vulnerable Dependencies Found: ${limitedResults.vulnerableDependencies}`);
    doc.moveDown();
    
    if (limitedResults.results && limitedResults.results.length > 0) {
      doc.fontSize(16).text('Vulnerabilities Found:', 100, doc.y);
      doc.moveDown();
      
      limitedResults.results.forEach((result, index) => {
        if (doc.y > 650) {
          doc.addPage();
        }
        
        doc.fontSize(12).text(`${index + 1}. ${result.dependency}@${result.version}`, { underline: true });
        doc.moveDown(0.3);
        
        result.vulnerabilities.forEach((vuln, vulnIndex) => {
          doc.fontSize(10);
          doc.text(`   ${vulnIndex + 1}. ${vuln.id} - ${vuln.severity} (Score: ${vuln.score})`);
          doc.text(`      Description: ${vuln.description.substring(0, 100)}...`);
          doc.moveDown(0.2);
        });
        
        doc.moveDown();
      });
    } else {
      doc.text('No vulnerabilities found!', 100, doc.y);
    }
    
    doc.end();
    
  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({ error: 'Failed to generate PDF' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});
