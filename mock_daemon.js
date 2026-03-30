const http = require('http');

let files = [
  { id:'3f2a1b4c-0000-0000-0000-000000000001', label:'Q3 Financial Report', opens:4, max_opens:10,
    fails:1, wiped:false, revoked:false, expires:'2025-12-31', sensitivity:'Confidential',
    has_decoy:true, require_token:false },
  { id:'3f2a1b4c-0000-0000-0000-000000000002', label:'Product Roadmap 2025', opens:12, max_opens:null,
    fails:0, wiped:false, revoked:false, expires:null, sensitivity:'Internal',
    has_decoy:false, require_token:false }
];

let logs = [
  { time: new Date().toISOString(), outcome:'grant',  device:'MacBook-Pro-M2',   file:'3f2a1b4c-0000-0000-0000-000000000001' }
];

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') { res.end(); return; }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathParts = url.pathname.split('/').filter(Boolean);

  // GET /api/health
  if (req.method === 'GET' && url.pathname === '/api/health') {
    res.end(JSON.stringify({ status: 'ok', version: 'mock-1.0.0' }));
    return;
  }

  // POST /api/files
  if (req.method === 'POST' && url.pathname === '/api/files') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const data = JSON.parse(body);
      const newFile = { ...data, id: data.file_id || Math.random().toString(36).substring(7), opens:0, fails:0, wiped:false, revoked:false };
      files.push(newFile);
      res.writeHead(201);
      res.end(JSON.stringify(newFile));
    });
    return;
  }

  // GET /api/files/:id/access-log
  if (req.method === 'GET' && pathParts[0] === 'api' && pathParts[1] === 'files' && pathParts[3] === 'access-log') {
    const fileId = pathParts[2];
    res.end(JSON.stringify(logs.filter(l => l.file === fileId)));
    return;
  }

  // POST /api/files/:id/revoke
  if (req.method === 'POST' && pathParts[0] === 'api' && pathParts[1] === 'files' && pathParts[3] === 'revoke') {
    const fileId = pathParts[2];
    const file = files.find(f => f.id === fileId);
    if (file) file.revoked = true;
    res.end(JSON.stringify({ status: 'revoked' }));
    return;
  }

  // POST /api/files/:id/wipe
  if (req.method === 'POST' && pathParts[0] === 'api' && pathParts[1] === 'files' && pathParts[3] === 'wipe') {
    const fileId = pathParts[2];
    const file = files.find(f => f.id === fileId);
    if (file) { file.wiped = true; file.revoked = true; }
    res.end(JSON.stringify({ status: 'wiped' }));
    return;
  }

  // 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(8743, '0.0.0.0', () => {
  console.log('Mock MindLock daemon running on http://0.0.0.0:8743');
});
