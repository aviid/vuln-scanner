import 'bootstrap/dist/css/bootstrap.min.css';
import './globals.css';

export const metadata = {
  title: 'Vuln Scanner - Dependency Vulnerability Scanner',
  description: 'Comprehensive vulnerability scanner for package.json, composer.json, and requirements.txt files',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        {/* Add Bootstrap Icons CDN */}
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" />
      </head>
      <body>{children}</body>
    </html>
  );
}