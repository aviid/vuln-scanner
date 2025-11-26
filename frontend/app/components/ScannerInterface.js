'use client';

import { useState, useRef } from 'react';
import axios from 'axios';
import { saveAs } from 'file-saver';

export default function ScannerInterface() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileType, setFileType] = useState('package.json');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileSelect = (file) => {
    if (file.name === 'package.json') {
      setFileType('package.json');
    } else if (file.name === 'composer.json') {
      setFileType('composer.json');
    } else if (file.name === 'requirements.txt') {
      setFileType('requirements.txt');
    } else {
      setError('Please select a valid package.json, composer.json, or requirements.txt file');
      return;
    }
    
    setSelectedFile(file);
    setError('');
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    
    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      setError('Please select a file first');
      return;
    }

    setIsScanning(true);
    setError('');

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('fileType', fileType);

    try {
      const response = await axios.post('http://localhost:5000/api/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      setScanResults(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to scan file. Make sure the backend server is running on port 5000.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleGeneratePDF = async () => {
    if (!scanResults) return;

    try {
      const response = await axios.post(
        'http://localhost:5000/api/generate-pdf',
        { scanResults, title: 'Vulnerability Scan Report' },
        { responseType: 'blob' }
      );

      const blob = new Blob([response.data], { type: 'application/pdf' });
      saveAs(blob, `vulnerability-report-${scanResults.scanId}.pdf`);
    } catch (err) {
      setError('Failed to generate PDF');
    }
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'bg-danger';
      case 'medium':
        return 'bg-warning';
      case 'low':
        return 'bg-info';
      default:
        return 'bg-secondary';
    }
  };

  return (
    <div className="container py-5">
      <div className="text-center mb-5">
        <h1 className="display-4 fw-bold">Vuln Scanner</h1>
        <p className="lead text-muted">
          Comprehensive vulnerability scanning for your dependencies
        </p>
      </div>

      <div className="row justify-content-center">
        <div className="col-md-8">
          <div className="card shadow-sm upload-card">
            <div className="card-body p-4">
              <h5 className="card-title mb-4">Upload Dependency File</h5>
              
              <div 
                className={`upload-area p-5 text-center ${isDragging ? 'dragover' : ''}`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <i className="bi bi-cloud-arrow-up display-4 text-muted mb-3"></i>
                <p className="mb-2">
                  {selectedFile ? selectedFile.name : 'Drag & drop your file here or click to browse'}
                </p>
                <p className="text-muted small">
                  Supports: package.json, composer.json, requirements.txt
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  className="d-none"
                  onChange={handleFileChange}
                  accept=".json,.txt"
                />
              </div>

              {error && (
                <div className="alert alert-danger mt-3" role="alert">
                  {error}
                </div>
              )}

              <div className="mt-4">
                <button
                  className="btn btn-primary btn-lg w-100"
                  onClick={handleScan}
                  disabled={isScanning || !selectedFile}
                >
                  {isScanning ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                      Scanning Dependencies...
                    </>
                  ) : (
                    'Scan for Vulnerabilities'
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {scanResults && (
        <div className="row justify-content-center mt-5">
          <div className="col-12">
            <div className="card shadow-sm">
              <div className="card-header bg-white d-flex justify-content-between align-items-center">
                <h5 className="mb-0">Scan Results</h5>
                <button
                  className="btn btn-outline-primary btn-sm"
                  onClick={handleGeneratePDF}
                >
                  <i className="bi bi-download me-2"></i>
                  Export PDF
                </button>
              </div>
              <div className="card-body">
                <div className="row mb-4">
                  <div className="col-md-3">
                    <div className="card bg-light">
                      <div className="card-body text-center">
                        <h3 className="text-primary">{scanResults.totalDependencies}</h3>
                        <p className="mb-0 text-muted">Total Dependencies</p>
                      </div>
                    </div>
                  </div>
                  <div className="col-md-3">
                    <div className="card bg-light">
                      <div className="card-body text-center">
                        <h3 className="text-warning">{scanResults.vulnerableDependencies}</h3>
                        <p className="mb-0 text-muted">Vulnerable Packages</p>
                      </div>
                    </div>
                  </div>
                  <div className="col-md-3">
                    <div className="card bg-light">
                      <div className="card-body text-center">
                        <h3 className="text-danger">
                          {scanResults.results.reduce((total, result) => total + result.vulnerabilities.length, 0)}
                        </h3>
                        <p className="mb-0 text-muted">Total Vulnerabilities</p>
                      </div>
                    </div>
                  </div>
                  <div className="col-md-3">
                    <div className="card bg-light">
                      <div className="card-body text-center">
                        <h6 className="text-muted">
                          {new Date(scanResults.timestamp).toLocaleDateString()}
                        </h6>
                        <p className="mb-0 text-muted">Scan Date</p>
                      </div>
                    </div>
                  </div>
                </div>

                {scanResults.results.length > 0 ? (
                  <div className="scan-results">
                    {scanResults.results.map((result, index) => (
                      <div key={index} className="card vulnerability-card mb-3">
                        <div className="card-body">
                          <div className="d-flex justify-content-between align-items-start mb-3">
                            <div>
                              <h6 className="card-title text-danger mb-1">
                                {result.dependency} @ {result.version}
                              </h6>
                              <span className="badge bg-secondary">{result.type}</span>
                            </div>
                            <span className="badge bg-danger">
                              {result.vulnerabilities.length} vulnerabilities
                            </span>
                          </div>

                          {result.vulnerabilities.map((vuln, vulnIndex) => (
                            <div key={vulnIndex} className="border-start border-3 border-danger ps-3 mb-3">
                              <div className="d-flex justify-content-between align-items-center mb-2">
                                <strong className="text-dark">{vuln.id}</strong>
                                <span className={`badge ${getSeverityBadgeClass(vuln.severity)}`}>
                                  {vuln.severity} (CVSS: {vuln.score})
                                </span>
                              </div>
                              <p className="text-muted small mb-2">{vuln.description}</p>
                              <div className="small">
                                <strong>Published:</strong> {new Date(vuln.published).toLocaleDateString()}
                              </div>
                              {vuln.references && vuln.references.length > 0 && (
                                <div className="mt-2">
                                  <strong>References:</strong>
                                  <ul className="small mt-1">
                                    {vuln.references.slice(0, 3).map((ref, refIndex) => (
                                      <li key={refIndex}>
                                        <a href={ref} target="_blank" rel="noopener noreferrer" className="text-decoration-none">
                                          {ref.substring(0, 80)}...
                                        </a>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-4">
                    <i className="bi bi-shield-check display-4 text-success mb-3"></i>
                    <h5 className="text-success">No Vulnerabilities Found!</h5>
                    <p className="text-muted">All dependencies appear to be secure.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}