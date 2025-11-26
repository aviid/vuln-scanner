# Vuln Scanner - Dependency Vulnerability Scanner

![Vuln Scanner](https://i.postimg.cc/BQWyY434/vulneribility-scanner.png)

A comprehensive full-stack application that scans dependency files for security vulnerabilities using real-time APIs from NVD, Snyk, and OSS Index.

## Features

- **Multi-Format Support** - Scan `package.json`, `composer.json`, and `requirements.txt`
- **Real API Integration** - Live vulnerability data from NVD, Snyk, OSS Index
- **Detailed Reports** - Comprehensive vulnerability analysis with severity ratings
- **PDF Export** - Generate professional vulnerability reports
- **Modern UI** - Bootstrap 5 responsive design
- **Real-time Scanning** - Live progress indicators and results

## 🛠️ Tech Stack

**Frontend:**
- Next.js 14
- React 18
- Bootstrap 5
- Axios for API calls

**Backend:**
- Node.js
- Express.js
- Multiple Security APIs (NVD, Snyk, OSS Index)
- PDFKit for report generation

## Quick Start

### Prerequisites
- Node.js 16+
- npm or yarn
- API keys for security services (optional)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/vuln-scanner.git
cd vuln-scanner
```

2. **Backend Setup**
```bash
cd backend
npm install
cp .env.example .env
# Add your API keys to .env
npm run dev
```

3. **Frontend Setup**
```bash
cd frontend
npm install
npm run dev
```

4. **Access the Application**
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000

## Project Structure

```
vuln-scanner/
├── backend/
│   ├── server.js          # Express server
│   ├── package.json       # Backend dependencies
│   └── uploads/           # Temporary file storage
├── frontend/
│   ├── app/               # Next.js app directory
│   │   ├── layout.js      # Root layout
│   │   ├── page.js        # Home page
│   │   ├── globals.css    # Global styles
│   │   └── components/    # React components
│   └── package.json       # Frontend dependencies
└── README.md
```

## Configuration

### API Keys (Optional)
Create `.env` in backend directory:
```env
NVD_API_KEY=your_nvd_key
SNYK_API_TOKEN=your_snyk_token
SNYK_ORG_ID=your_snyk_org
OSS_INDEX_API_KEY=your_oss_index_key
PORT=5000
```

### Supported Dependency Files
- **package.json** - Node.js dependencies
- **composer.json** - PHP dependencies  
- **requirements.txt** - Python dependencies

## Usage

1. **Upload Dependency File**
   - Drag & drop or click to browse
   - Supports package.json, composer.json, requirements.txt

2. **Scan for Vulnerabilities**
   - Real-time scanning progress
   - Multiple API integration
   - Comprehensive vulnerability database

3. **View Results**
   - Severity-based color coding
   - CVSS scores and descriptions
   - Reference links for each vulnerability

4. **Export Reports**
   - Generate PDF reports
   - Professional formatting
   - Scan summary and details

## Sample Results

The scanner provides:
- **Total Dependencies** scanned
- **Vulnerable Packages** identified  
- **Total Vulnerabilities** found
- **Scan timestamp** for tracking

## Security Features

- Local file processing (no cloud storage)
- Secure API communication
- Input validation and sanitization
- No sensitive data persistence

## Troubleshooting

### Common Issues
- **API Rate Limits**: Add API keys for higher limits
- **File Upload Errors**: Check file format and size
- **PDF Generation**: Ensure proper file permissions

### Debug Mode
```bash
# Enable debug logging
DEBUG=true npm run dev
```

## Contributing

We welcome contributions! Please feel free to submit pull requests or open issues.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **National Vulnerability Database (NVD)** for vulnerability data
- **Snyk** for security intelligence
- **OSS Index** for open source vulnerability data
- **Bootstrap** for the UI framework

## Support

For support and questions:
- Open an [issue](https://github.com/yourusername/vuln-scanner/issues)
- Check the [troubleshooting](#troubleshooting) section

---

<div align="center">

**Secure Your Dependencies • Scan with Confidence**

*Built with love for the developer community*

</div>
