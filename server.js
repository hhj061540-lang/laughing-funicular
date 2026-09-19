const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { exec, spawn, execSync } = require('child_process');
const simpleGit = require('simple-git');

// ============ GIT IDENTITY BOOTSTRAP ============
(function configureGit() {
    const cmds = [
        'git config --global user.name "Git Server"',
        'git config --global user.email "git@localhost"',
        'git config --global init.defaultBranch main',
        'git config --global --add safe.directory "*"'
    ];
    for (const c of cmds) {
        try { execSync(c, { stdio: 'pipe' }); }
        catch (e) { console.warn('git bootstrap:', c, '→', e.message.split('\n')[0]); }
    }
    try {
        const n = execSync('git config --global user.name').toString().trim();
        const m = execSync('git config --global user.email').toString().trim();
        console.log(`✅ Git identity ready: ${n} <${m}>`);
    } catch (e) {
        console.error('❌ Git identity NOT configured:', e.message);
    }
})();

const app = express();
const PORT = process.env.PORT || 5900;
const REPO_ROOT = process.env.REPO_ROOT || path.join(__dirname, 'repositories');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const APPS_FILE = path.join(DATA_DIR, 'oauth-apps.json');
const SECRET_FILE = path.join(DATA_DIR, 'oauth-secret.key');
const REVOKED_TOKENS_FILE = path.join(DATA_DIR, 'revoked-tokens.json');
const CODESPACES_FILE = path.join(DATA_DIR, 'codespaces.json');
const ISSUES_FILE = path.join(DATA_DIR, 'issues.json');
const AUTH_CODES_FILE = path.join(DATA_DIR, 'auth-codes.json');
const RELEASES_FILE = path.join(DATA_DIR, 'releases.json');
const RELEASE_ASSETS_DIR = path.join(DATA_DIR, 'release-assets');

fs.mkdirSync(REPO_ROOT, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(path.join(__dirname, 'codespaces'), { recursive: true });
fs.mkdirSync(RELEASE_ASSETS_DIR, { recursive: true });

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(APPS_FILE)) fs.writeFileSync(APPS_FILE, '[]');
if (!fs.existsSync(REVOKED_TOKENS_FILE)) fs.writeFileSync(REVOKED_TOKENS_FILE, '[]');
if (!fs.existsSync(CODESPACES_FILE)) fs.writeFileSync(CODESPACES_FILE, '[]');
if (!fs.existsSync(ISSUES_FILE)) fs.writeFileSync(ISSUES_FILE, '[]');
if (!fs.existsSync(AUTH_CODES_FILE)) fs.writeFileSync(AUTH_CODES_FILE, '[]');
if (!fs.existsSync(RELEASES_FILE)) fs.writeFileSync(RELEASES_FILE, '[]');

let OAUTH_SECRET;
if (fs.existsSync(SECRET_FILE)) {
    OAUTH_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
} else {
    OAUTH_SECRET = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync(SECRET_FILE, OAUTH_SECRET, { mode: 0o600 });
}

const deviceCodes = new Map();
const activeSessions = new Map();

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const { repoName, tagName } = req.params;
        const assetDir = path.join(RELEASE_ASSETS_DIR, repoName, tagName);
        fs.mkdirSync(assetDir, { recursive: true });
        cb(null, assetDir);
    },
    filename: (req, file, cb) => cb(null, file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'))
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// ============ HELPERS ============
function readJson(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return []; } }
function writeJson(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2)); }
function randomHex(bytes) { return crypto.randomBytes(bytes).toString('hex'); }
function generateClientId() { return 'client_' + randomHex(16); }
function generateClientSecret() { return 'secret_' + randomHex(32); }
function generateDeviceCode() { return crypto.randomBytes(4).toString('hex').toUpperCase(); }
function hashPassword(password) { return crypto.createHash('sha256').update(password).digest('hex'); }
function baseUrl(req) {
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    return `${protocol}://${req.get('host')}`;
}
function isTokenRevoked(jti) {
    if (!jti) return false;
    return readJson(REVOKED_TOKENS_FILE).some(item => item.jti === jti);
}
function revokeToken(jti, exp) {
    const revoked = readJson(REVOKED_TOKENS_FILE);
    if (revoked.some(item => item.jti === jti)) return;
    revoked.push({ jti, exp: exp || null, revokedAt: new Date().toISOString() });
    writeJson(REVOKED_TOKENS_FILE, revoked);
}
function generateCodeChallenge(codeVerifier, method = 'S256') {
    if (method === 'S256') {
        return crypto.createHash('sha256').update(codeVerifier).digest('base64')
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    return codeVerifier;
}
function generateCodeVerifier() { return randomHex(32); }

function getGitBackendPath() {
    const paths = [
        '/usr/lib/git-core/git-http-backend',
        '/usr/libexec/git-core/git-http-backend',
        '/usr/local/libexec/git-core/git-http-backend'
    ];
    for (const p of paths) if (fs.existsSync(p)) return p;
    try {
        const gp = execSync('git --exec-path').toString().trim();
        const bp = path.join(gp, 'git-http-backend');
        if (fs.existsSync(bp)) return bp;
    } catch (e) {}
    return 'git-http-backend';
}
const GIT_BACKEND_BIN = getGitBackendPath();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ============ MIDDLEWARE ============
function authenticateJWT(req, res, next) {
    const authorization = req.headers.authorization || '';
    if (!authorization.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'unauthorized', message: 'Bearer access token required' });
    }
    const token = authorization.substring(7);
    try {
        const decoded = jwt.verify(token, OAUTH_SECRET);
        if (decoded.jti && isTokenRevoked(decoded.jti)) {
            return res.status(401).json({ error: 'invalid_token', message: 'Token has been logged out' });
        }
        req.user = decoded;
        req.accessToken = token;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'invalid_token', message: 'Invalid or expired access token' });
    }
}
function optionalAuth(req, res, next) {
    const authorization = req.headers.authorization || '';
    if (authorization.startsWith('Bearer ')) {
        try { req.user = jwt.verify(authorization.substring(7), OAUTH_SECRET); } catch (e) {}
    }
    next();
}

// ============ DASHBOARD ============
const htmlContent = `<!DOCTYPE html><html><head><title>Unified Git & OAuth</title><style>
body{font-family:monospace;background:#121212;color:#00ff66;padding:20px;}
h1,h2{border-bottom:1px solid #333;padding-bottom:5px;}
.menu{background:#1e1e1e;padding:10px;border-radius:5px;margin-bottom:20px;display:flex;gap:10px;flex-wrap:wrap;}
.menu a{color:#00ff66;text-decoration:none;padding:8px 15px;background:#2b2b2b;border-radius:3px;border:1px solid #444;}
.menu a:hover{background:#0088cc;}
form{margin-bottom:15px;background:#1e1e1e;padding:15px;border-radius:5px;}
input,textarea,button{background:#2b2b2b;color:#fff;border:1px solid #444;padding:8px;margin:4px 0;width:98%;font-family:monospace;}
button{cursor:pointer;background:#0088cc;font-weight:bold;}
button:hover{background:#00aaff;}
pre{background:#000;padding:10px;border:1px solid #333;overflow-x:auto;color:#fff;}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
.code-box{background:#000;color:#00ff66;padding:10px;border:1px solid #00ff66;word-break:break-all;}
.section{background:#1a1a1a;padding:15px;border-radius:5px;margin-bottom:20px;}
</style></head><body>
<h1>🚀 Unified Git & OAuth Dashboard</h1>
<div class="menu">
<a href="/dashboard">🏠 Home</a>
<a href="/codespaces/menu">💻 Codespaces</a>
<a href="/issues/menu">📝 Issues</a>
<a href="/releases/menu">📦 Releases</a>
<a href="/api/oauth/apps">🔐 OAuth Apps</a>
<a href="/api/list-repos">📁 Repositories</a>
<a href="/api/auth/login">🔑 Login</a>
</div>
<p>Port: ${PORT}</p>
<div class="grid">
<div class="section"><h2>📁 1. Create Repository</h2>
<form action="/create-repo" method="POST">
<input type="text" name="repoName" placeholder="Repository Name" required>
<button type="submit">Create</button></form></div>
<div class="section"><h2>🔗 2. Clone URL</h2>
<form action="/get-clone-url" method="GET">
<input type="text" name="repoName" placeholder="Repository Name" required>
<button type="submit">Get URL</button></form></div>
<div class="section"><h2>📄 3. Pipeline File</h2>
<form action="/create-yml" method="POST">
<input type="text" name="repoName" placeholder="Repository Name" required>
<input type="text" name="ymlFileName" placeholder="File Name" required>
<textarea name="ymlContents" rows="4" placeholder="Contents"></textarea>
<button type="submit">Save & Commit</button></form></div>
<div class="section"><h2>🏷️ 4. Release & Tag</h2>
<form action="/create-release" method="POST">
<input type="text" name="repoName" placeholder="Repository Name" required>
<input type="text" name="tagName" placeholder="Tag" required>
<button type="submit">Create</button></form></div>
<div class="section"><h2>🌿 5. Branch & Logs</h2>
<form action="/create-branch" method="POST">
<input type="text" name="repoName" placeholder="Repository Name" required>
<input type="text" name="branchName" placeholder="Branch" required>
<button type="submit">Create Branch</button></form>
<form action="/logs" method="GET" style="margin-top:10px;">
<input type="text" name="repoName" placeholder="Repository Name" required>
<button type="submit">View Logs</button></form></div>
<div class="section"><h2>⚙️ 6. Pipeline Runner</h2>
<form action="/run-pipeline" method="POST">
<input type="text" name="repoName" placeholder="Repository Name" required>
<input type="text" name="pipelineFile" placeholder="Pipeline File" required>
<button type="submit">Run</button></form>
<form action="/pipeline-logs" method="GET" style="margin-top:10px;">
<input type="text" name="repoName" placeholder="Repository Name" required>
<button type="submit">Fetch Logs</button></form></div>
</div>
<h2>📋 Repositories</h2>
<button onclick="fetchRepos()">Fetch</button>
<pre id="repoOutput"></pre>
<script>
function fetchRepos(){const t=prompt('Bearer Token:');
fetch('/api/list-repos',{headers:{'Authorization':'Bearer '+t}})
.then(r=>r.json()).then(d=>document.getElementById('repoOutput').textContent=JSON.stringify(d,null,2))
.catch(e=>document.getElementById('repoOutput').textContent='Error: '+e);}
</script></body></html>`;
app.get('/dashboard', (req, res) => res.send(htmlContent));
app.get('/', (req, res) => res.send(htmlContent));

// ============ MENUS ============
function menuPage(title, bodyHtml, scripts = '') {
    return `<!DOCTYPE html><html><head><title>${title}</title><style>
body{font-family:monospace;background:#121212;color:#00ff66;padding:20px;}
h1{border-bottom:1px solid #333;padding-bottom:5px;}
.menu{background:#1e1e1e;padding:10px;border-radius:5px;margin-bottom:20px;display:flex;gap:10px;flex-wrap:wrap;}
.menu a{color:#00ff66;text-decoration:none;padding:8px 15px;background:#2b2b2b;border-radius:3px;border:1px solid #444;}
.menu a:hover{background:#0088cc;}
form{background:#1e1e1e;padding:15px;border-radius:5px;margin-bottom:15px;}
input,textarea,button{background:#2b2b2b;color:#fff;border:1px solid #444;padding:8px;margin:4px 0;width:98%;font-family:monospace;}
button{cursor:pointer;background:#0088cc;font-weight:bold;}
button:hover{background:#00aaff;}
pre{background:#000;padding:10px;border:1px solid #333;overflow-x:auto;color:#fff;}
</style></head><body>
<div class="menu">
<a href="/dashboard">🏠 Home</a>
<a href="/codespaces/menu">💻 Codespaces</a>
<a href="/issues/menu">📝 Issues</a>
<a href="/releases/menu">📦 Releases</a>
</div>
<h1>${title}</h1>${bodyHtml}<script>${scripts}</script></body></html>`;
}

app.get('/codespaces/menu', (req, res) => res.send(menuPage('💻 Codespaces', `
<h2>Create</h2>
<form id="cf"><input id="repoName" placeholder="Repository Name" required>
<input id="branch" placeholder="Branch" value="main">
<input id="machine" placeholder="Machine" value="basic">
<input id="token" placeholder="Bearer Token" required>
<button type="submit">Create</button></form>
<h2>List</h2><button onclick="list()">Refresh</button><pre id="out"></pre>`, `
async function create(e){e.preventDefault();
const r=await fetch('/codespaces/create',{method:'POST',
headers:{'Authorization':'Bearer '+document.getElementById('token').value,'Content-Type':'application/json'},
body:JSON.stringify({repoName:document.getElementById('repoName').value,
branch:document.getElementById('branch').value,machine:document.getElementById('machine').value})});
alert(JSON.stringify(await r.json(),null,2));}
async function list(){const t=prompt('Bearer Token:');
const r=await fetch('/codespaces/list',{headers:{'Authorization':'Bearer '+t}});
document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
document.getElementById('cf').addEventListener('submit',create);`)));

app.get('/issues/menu', (req, res) => res.send(menuPage('📝 Issues', `
<h2>Create Issue</h2>
<form id="cf"><input id="repo" placeholder="Repository Name" required>
<input id="title" placeholder="Title" required>
<textarea id="desc" rows="4" placeholder="Description"></textarea>
<input id="labels" placeholder="Labels (comma-separated)">
<input id="token" placeholder="Bearer Token" required>
<button type="submit">Create</button></form>
<h2>List</h2><button onclick="list()">Refresh</button><pre id="out"></pre>`, `
async function create(e){e.preventDefault();
const r=await fetch('/issues/create',{method:'POST',
headers:{'Authorization':'Bearer '+document.getElementById('token').value,'Content-Type':'application/json'},
body:JSON.stringify({repoName:document.getElementById('repo').value,
title:document.getElementById('title').value,
description:document.getElementById('desc').value,
labels:document.getElementById('labels').value.split(',').map(s=>s.trim()).filter(Boolean)})});
alert(JSON.stringify(await r.json(),null,2));}
async function list(){const t=prompt('Bearer Token:');
const r=await fetch('/issues/list',{headers:{'Authorization':'Bearer '+t}});
document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
document.getElementById('cf').addEventListener('submit',create);`)));

app.get('/releases/menu', (req, res) => res.send(menuPage('📦 Releases', `
<h2>Create Release</h2>
<form id="cr"><input id="repoName" placeholder="Repository Name" required>
<input id="tagName" placeholder="Tag (e.g., v1.0.0)" required>
<input id="releaseName" placeholder="Release Name (optional)">
<textarea id="releaseBody" rows="3" placeholder="Notes"></textarea>
<input id="token" placeholder="Bearer Token" required>
<button type="submit">Create</button></form>
<h2>Upload Asset</h2>
<form id="uf" enctype="multipart/form-data">
<input id="urepo" placeholder="Repository Name" required>
<input id="utag" placeholder="Tag" required>
<input type="file" id="assetFile" required>
<input id="utoken" placeholder="Bearer Token" required>
<button type="submit">Upload</button></form>
<h2>Releases</h2><button onclick="list()">Refresh</button><pre id="out"></pre>`, `
async function create(e){e.preventDefault();
const r=await fetch('/api/releases/create',{method:'POST',
headers:{'Authorization':'Bearer '+document.getElementById('token').value,'Content-Type':'application/json'},
body:JSON.stringify({repoName:document.getElementById('repoName').value,
tagName:document.getElementById('tagName').value,
releaseName:document.getElementById('releaseName').value,
releaseBody:document.getElementById('releaseBody').value})});
alert(JSON.stringify(await r.json(),null,2));list();}
async function upload(e){e.preventDefault();
const fd=new FormData();fd.append('asset',document.getElementById('assetFile').files[0]);
const r=await fetch('/api/releases/'+document.getElementById('urepo').value+'/'+document.getElementById('utag').value+'/assets',
{method:'POST',headers:{'Authorization':'Bearer '+document.getElementById('utoken').value},body:fd});
alert(JSON.stringify(await r.json(),null,2));list();}
async function list(){const r=await fetch('/api/releases/list');
document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);}
document.getElementById('cr').addEventListener('submit',create);
document.getElementById('uf').addEventListener('submit',upload);list();`)));

// ============ REPOSITORIES ============
app.post('/create-repo', authenticateJWT, async (req, res) => {
    try {
        const { repoName } = req.body;
        if (!repoName) return res.status(400).send('repoName required');
        const repoPath = path.join(REPO_ROOT, repoName);
        const host = req.get('host');
        if (fs.existsSync(repoPath)) return res.send(`<pre>⚠️ Repository already exists.</pre><a href="/dashboard">Back</a>`);

        fs.mkdirSync(repoPath, { recursive: true });
        const git = simpleGit(repoPath);
        await git.init();
        await git.addConfig('http.receivepack', 'true');
        await git.addConfig('receive.denyCurrentBranch', 'updateInstead');

        fs.writeFileSync(path.join(repoPath, 'README.md'),
            `# ${repoName}\n\nInitialized at ${new Date().toISOString()}\n`);
        await git.add('README.md');
        await git.commit('Initial commit');

        res.send(`<pre>✅ Repository '${repoName}' created.</pre>
        <p>Clone:</p><div class="code-box">git clone https://${host}/repos/${repoName}.git</div>
        <br/><a href="/dashboard">Back</a>`);
    } catch (err) {
        console.error('create-repo error:', err);
        res.status(500).send(`<pre>Error: ${err.message}</pre><a href="/dashboard">Back</a>`);
    }
});

app.get('/get-clone-url', authenticateJWT, (req, res) => {
    const { repoName } = req.query;
    const url = `https://${req.get('host')}/repos/${repoName}.git`;
    res.send(`<h2>🔗 Clone URL</h2><div class="code-box">git clone ${url}</div><br/><a href="/dashboard">Back</a>`);
});

app.get('/api/list-repos', authenticateJWT, (req, res) => {
    try {
        const host = req.get('host');
        if (!fs.existsSync(REPO_ROOT)) return res.json({ status: 'success', repositories: [] });
        const repos = fs.readdirSync(REPO_ROOT)
            .filter(f => fs.statSync(path.join(REPO_ROOT, f)).isDirectory())
            .map(repo => ({
                name: repo,
                cloneUrl: `https://${host}/repos/${repo}.git`,
                siteUrl: `https://${host}/sites/${repo}/`,
                releasesUrl: `https://${host}/releases/${repo}`
            }));
        res.json({ status: 'success', repositories: repos });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/view-repos', authenticateJWT, (req, res) => res.redirect('/api/list-repos'));

app.post('/create-yml', authenticateJWT, async (req, res) => {
    try {
        const { repoName, ymlFileName, ymlContents } = req.body;
        if (!repoName || !ymlFileName || ymlContents === undefined) return res.status(400).send('Missing fields');
        if (repoName.includes('..') || ymlFileName.includes('..') || path.isAbsolute(ymlFileName)) return res.status(400).send('Invalid path');
        const repoPath = path.join(REPO_ROOT, repoName);
        if (!fs.existsSync(repoPath)) return res.status(404).send(`Repo not found`);

        const target = path.join(repoPath, ymlFileName);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, ymlContents);

        const git = simpleGit(repoPath);
        await git.add(ymlFileName);
        try { await git.commit(`Added/updated ${ymlFileName}`); }
        catch (e) { if (!/nothing to commit/i.test(e.message)) throw e; }

        res.send(`<pre>✅ File '${ymlFileName}' committed.</pre><a href="/dashboard">Back</a>`);
    } catch (err) {
        console.error('create-yml error:', err);
        res.status(500).send(`<pre>Error: ${err.message}</pre><a href="/dashboard">Back</a>`);
    }
});

app.get('/raw', authenticateJWT, (req, res) => {
    const { repoName, filePath } = req.query;
    const fullPath = path.join(REPO_ROOT, repoName, filePath);
    if (!fullPath.startsWith(REPO_ROOT)) return res.status(400).send('Invalid path');
    if (fs.existsSync(fullPath)) { res.type('text/plain'); res.sendFile(fullPath); }
    else res.status(404).send('File not found');
});

app.post('/create-branch', authenticateJWT, async (req, res) => {
    try {
        const { repoName, branchName } = req.body;
        await simpleGit(path.join(REPO_ROOT, repoName)).checkoutLocalBranch(branchName);
        res.send(`<pre>✅ Branch '${branchName}' created.</pre><a href="/dashboard">Back</a>`);
    } catch (err) { res.send(`<pre>Error: ${err.message}</pre><a href="/dashboard">Back</a>`); }
});

app.get('/logs', authenticateJWT, async (req, res) => {
    try {
        const logs = await simpleGit(path.join(REPO_ROOT, req.query.repoName)).log();
        res.type('text/plain').send(JSON.stringify(logs, null, 2));
    } catch (err) { res.status(500).send(`Error: ${err.message}`); }
});

app.post('/run-pipeline', authenticateJWT, (req, res) => {
    const { repoName, pipelineFile } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    const target = path.join(repoPath, pipelineFile);
    const logFile = path.join(repoPath, 'pipeline-execution.log');
    if (!fs.existsSync(target)) return res.status(404).send('Pipeline file not found');
    exec(`cd "${repoPath}" && echo "Executing ${pipelineFile}..."`, (error, stdout, stderr) => {
        const output = error ? `Error:\n${stderr}` : `Output:\n${stdout}`;
        fs.appendFileSync(logFile, `\n--- [${new Date().toISOString()}] ---\n${output}`);
        res.send(`<pre>${output}</pre><a href="/dashboard">Back</a>`);
    });
});

app.get('/pipeline-logs', authenticateJWT, (req, res) => {
    const logFile = path.join(REPO_ROOT, req.query.repoName, 'pipeline-execution.log');
    if (fs.existsSync(logFile)) res.type('text/plain').sendFile(logFile);
    else res.status(404).send('No logs');
});

// ============ RELEASES ============
app.post('/api/releases/create', authenticateJWT, async (req, res) => {
    const { repoName, tagName, releaseName, releaseBody } = req.body;
    if (!repoName || !tagName) return res.status(400).json({ error: 'repoName and tagName required' });
    const repoPath = path.join(REPO_ROOT, repoName);
    if (!fs.existsSync(repoPath)) return res.status(404).json({ error: 'Repository not found' });

    try {
        const git = simpleGit(repoPath);
        let hasCommit = true;
        try { await git.revparse(['HEAD']); } catch { hasCommit = false; }
        if (!hasCommit) {
            fs.writeFileSync(path.join(repoPath, 'README.md'), `# ${repoName}\n`);
            await git.add('README.md');
            await git.commit('Initial commit');
        }
        const tags = await git.tags();
        if (!tags.all.includes(tagName)) await git.addTag(tagName);

        const releases = readJson(RELEASES_FILE);
        if (releases.find(r => r.repoName === repoName && r.tagName === tagName)) {
            return res.status(409).json({ error: 'Release already exists' });
        }
        const release = {
            id: 'rel_' + randomHex(16), repoName, tagName,
            releaseName: releaseName || tagName, releaseBody: releaseBody || '',
            createdBy: req.user.username, createdAt: new Date().toISOString(), assets: [],
            downloadUrl: `${baseUrl(req)}/releases/download/${repoName}/${tagName}`,
            htmlUrl: `${baseUrl(req)}/releases/${repoName}/tag/${tagName}`
        };
        releases.push(release);
        writeJson(RELEASES_FILE, releases);
        fs.mkdirSync(path.join(RELEASE_ASSETS_DIR, repoName, tagName), { recursive: true });
        res.status(201).json({ status: 'success', message: 'Release created', release });
    } catch (err) {
        console.error('create-release error:', err);
        res.status(500).json({ error: 'Failed to create release', details: err.message });
    }
});

app.get('/api/releases/list', (req, res) => {
    const releases = readJson(RELEASES_FILE);
    const base = baseUrl(req);
    res.json({ releases: releases.map(r => ({
        ...r,
        assets: r.assets.map(a => ({ ...a, downloadUrl: `${base}/releases/download/${r.repoName}/${r.tagName}/${a.name}` }))
    })) });
});

app.get('/api/releases/:repoName', (req, res) => {
    const releases = readJson(RELEASES_FILE).filter(r => r.repoName === req.params.repoName);
    const base = baseUrl(req);
    res.json({ releases: releases.map(r => ({
        ...r,
        assets: r.assets.map(a => ({ ...a, downloadUrl: `${base}/releases/download/${r.repoName}/${r.tagName}/${a.name}` }))
    })) });
});

app.get('/api/releases/:repoName/:tagName', (req, res) => {
    const release = readJson(RELEASES_FILE).find(r => r.repoName === req.params.repoName && r.tagName === req.params.tagName);
    if (!release) return res.status(404).json({ error: 'Release not found' });
    const base = baseUrl(req);
    res.json({ release: {
        ...release,
        assets: release.assets.map(a => ({ ...a, downloadUrl: `${base}/releases/download/${release.repoName}/${release.tagName}/${a.name}` }))
    }});
});

app.post('/api/releases/:repoName/:tagName/assets', authenticateJWT, upload.single('asset'), (req, res) => {
    const { repoName, tagName } = req.params;
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const releases = readJson(RELEASES_FILE);
    const idx = releases.findIndex(r => r.repoName === repoName && r.tagName === tagName);
    if (idx === -1) { try { fs.unlinkSync(req.file.path); } catch {} return res.status(404).json({ error: 'Release not found' }); }

    const existing = releases[idx].assets.find(a => a.name === req.file.originalname);
    if (existing) {
        existing.size = req.file.size;
        existing.uploadedAt = new Date().toISOString();
        existing.uploadedBy = req.user.username;
    } else {
        releases[idx].assets.push({
            id: 'asset_' + randomHex(8),
            name: req.file.originalname,
            filename: req.file.filename,
            size: req.file.size,
            mimeType: req.file.mimetype,
            uploadedAt: new Date().toISOString(),
            uploadedBy: req.user.username
        });
    }
    releases[idx].updatedAt = new Date().toISOString();
    writeJson(RELEASES_FILE, releases);
    const asset = releases[idx].assets.find(a => a.name === req.file.originalname);
    res.status(201).json({ status: 'success', message: 'Asset uploaded',
        asset: { ...asset, downloadUrl: `${baseUrl(req)}/releases/download/${repoName}/${tagName}/${asset.name}` }});
});

app.delete('/api/releases/:repoName/:tagName/assets/:assetName', authenticateJWT, (req, res) => {
    const { repoName, tagName, assetName } = req.params;
    const releases = readJson(RELEASES_FILE);
    const idx = releases.findIndex(r => r.repoName === repoName && r.tagName === tagName);
    if (idx === -1) return res.status(404).json({ error: 'Release not found' });
    const ai = releases[idx].assets.findIndex(a => a.name === assetName);
    if (ai === -1) return res.status(404).json({ error: 'Asset not found' });
    try { fs.unlinkSync(path.join(RELEASE_ASSETS_DIR, repoName, tagName, releases[idx].assets[ai].filename)); } catch {}
    releases[idx].assets.splice(ai, 1);
    writeJson(RELEASES_FILE, releases);
    res.json({ status: 'success', message: 'Asset deleted' });
});

app.delete('/api/releases/:repoName/:tagName', authenticateJWT, async (req, res) => {
    const { repoName, tagName } = req.params;
    const releases = readJson(RELEASES_FILE);
    const idx = releases.findIndex(r => r.repoName === repoName && r.tagName === tagName);
    if (idx === -1) return res.status(404).json({ error: 'Release not found' });
    if (releases[idx].createdBy !== req.user.username) return res.status(403).json({ error: 'Access denied' });
    try { fs.rmSync(path.join(RELEASE_ASSETS_DIR, repoName, tagName), { recursive: true, force: true }); } catch {}
    try { await simpleGit(path.join(REPO_ROOT, repoName)).tag(['-d', tagName]); } catch {}
    releases.splice(idx, 1);
    writeJson(RELEASES_FILE, releases);
    res.json({ status: 'success', message: 'Release deleted' });
});

// ============ PUBLIC DOWNLOADS ============
app.get('/releases/download/:repoName/:tagName/:assetName', optionalAuth, (req, res) => {
    const { repoName, tagName, assetName } = req.params;
    const sRepo = repoName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const sTag = tagName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const releases = readJson(RELEASES_FILE);
    const release = releases.find(r => r.repoName === sRepo && r.tagName === sTag);
    if (!release) return res.status(404).json({ error: 'Release not found' });
    const asset = release.assets.find(a => a.name === assetName);
    if (!asset) return res.status(404).json({ error: 'Asset not found' });
    const assetPath = path.join(RELEASE_ASSETS_DIR, sRepo, sTag, asset.filename);
    if (!fs.existsSync(assetPath)) return res.status(404).json({ error: 'File missing' });
    asset.downloadCount = (asset.downloadCount || 0) + 1;
    asset.lastDownloadedAt = new Date().toISOString();
    writeJson(RELEASES_FILE, releases);
    res.setHeader('Content-Disposition', `attachment; filename="${asset.name}"`);
    res.setHeader('Content-Type', asset.mimeType || 'application/octet-stream');
    res.setHeader('Content-Length', asset.size);
    fs.createReadStream(assetPath).pipe(res);
});

app.get('/releases/download/:repoName/:tagName', optionalAuth, async (req, res) => {
    const { repoName, tagName } = req.params;
    const release = readJson(RELEASES_FILE).find(r => r.repoName === repoName && r.tagName === tagName);
    if (!release) return res.status(404).json({ error: 'Release not found' });
    const repoPath = path.join(REPO_ROOT, repoName);
    const tempDir = path.join(DATA_DIR, 'temp');
    fs.mkdirSync(tempDir, { recursive: true });
    const tarball = path.join(tempDir, `${repoName}-${tagName}.tar.gz`);
    try {
        execSync(`cd "${repoPath}" && git archive --format=tar.gz --output="${tarball}" ${tagName}`, { timeout: 30000 });
        res.setHeader('Content-Disposition', `attachment; filename="${repoName}-${tagName}.tar.gz"`);
        res.setHeader('Content-Type', 'application/gzip');
        const s = fs.createReadStream(tarball);
        s.pipe(res);
        s.on('end', () => { try { fs.unlinkSync(tarball); } catch {} });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create archive', details: err.message });
    }
});

app.get('/releases/:repoName/tag/:tagName', optionalAuth, (req, res) => {
    const { repoName, tagName } = req.params;
    const release = readJson(RELEASES_FILE).find(r => r.repoName === repoName && r.tagName === tagName);
    if (!release) return res.status(404).send('<h1>Release not found</h1>');
    const base = baseUrl(req);
    res.send(`<!DOCTYPE html><html><head><title>${release.tagName}</title>
    <style>body{font-family:monospace;background:#121212;color:#00ff66;padding:20px;max-width:900px;margin:0 auto;}
    h1{border-bottom:1px solid #333;padding-bottom:10px;}
    .asset{background:#000;padding:12px;margin:8px 0;border-radius:3px;display:flex;justify-content:space-between;align-items:center;border:1px solid #333;}
    .asset a{color:#00ff66;text-decoration:none;font-weight:bold;}
    .download-btn{background:#00aa44;color:#fff !important;padding:8px 16px;border-radius:3px;text-decoration:none !important;}</style>
    </head><body>
    <h1>📦 ${release.releaseName || release.tagName}</h1>
    <p><strong>Repo:</strong> ${release.repoName} | <strong>Tag:</strong> ${release.tagName}</p>
    <p><strong>Created:</strong> ${release.createdAt}</p>
    ${release.releaseBody ? `<pre style="background:#000;padding:10px;white-space:pre-wrap;">${release.releaseBody}</pre>` : ''}
    <p><a href="${base}/releases/download/${release.repoName}/${release.tagName}" class="download-btn" download>⬇️ Download Source (tar.gz)</a></p>
    <h2>📎 Assets</h2>
    ${release.assets.length ? release.assets.map(a => `
        <div class="asset"><div><strong>${a.name}</strong><br><small>${(a.size/1024).toFixed(2)} KB | Downloads: ${a.downloadCount||0}</small></div>
        <a href="${base}/releases/download/${release.repoName}/${release.tagName}/${a.name}" class="download-btn" download>⬇️ Download</a></div>`).join('') : '<p><em>No assets yet</em></p>'}
    </body></html>`);
});

app.post('/create-release', authenticateJWT, async (req, res) => {
    const { repoName, tagName } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    if (!fs.existsSync(repoPath)) return res.status(404).send('Repository not found.');
    try {
        const git = simpleGit(repoPath);
        let hasCommit = true;
        try { await git.revparse(['HEAD']); } catch { hasCommit = false; }
        if (!hasCommit) {
            fs.writeFileSync(path.join(repoPath, 'README.md'), `# ${repoName}\n`);
            await git.add('README.md');
            await git.commit('Initial commit');
        }
        await git.addTag(tagName);
        const host = req.get('host');
        res.send(`<h2>✅ Tag Created</h2>
        <p><a href="https://${host}/releases/${repoName}/tag/${tagName}" style="color:#00ff66;">https://${host}/releases/${repoName}/tag/${tagName}</a></p>
        <a href="/dashboard" style="color:#00ff66;">← Back</a>`);
    } catch (err) { res.status(500).send(`Error: ${err.message}`); }
});

// ============ CODESPACES ============
app.post('/codespaces/create', authenticateJWT, async (req, res) => {
    const { repoName, branch = 'main', machine = 'basic' } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    if (!fs.existsSync(repoPath)) return res.status(404).json({ error: 'Repository not found' });
    const id = 'cs_' + randomHex(16);
    const dir = path.join(__dirname, 'codespaces', id);
    fs.mkdirSync(dir, { recursive: true });
    try {
        await simpleGit().clone(repoPath, dir);
        await simpleGit(dir).checkout(branch);
    } catch (err) { return res.status(500).json({ error: 'Clone failed', details: err.message }); }
    const cs = { id, repoName, branch, machine, status: 'running',
        createdBy: req.user.username, createdAt: new Date().toISOString(), directory: dir };
    const list = readJson(CODESPACES_FILE);
    list.push(cs);
    writeJson(CODESPACES_FILE, list);
    activeSessions.set(id, cs);
    res.json({ status: 'success', codespace: { id, repoName, branch, status: 'running',
        url: `${baseUrl(req)}/codespaces/terminal/${id}` }});
});

app.get('/codespaces/list', authenticateJWT, (req, res) => {
    const list = readJson(CODESPACES_FILE).filter(c => c.createdBy === req.user.username);
    res.json({ codespaces: list });
});

app.post('/codespaces/exec/:id', authenticateJWT, (req, res) => {
    const cs = readJson(CODESPACES_FILE).find(c => c.id === req.params.id);
    if (!cs) return res.status(404).json({ error: 'Codespace not found' });
    if (cs.createdBy !== req.user.username) return res.status(403).json({ error: 'Access denied' });
    exec(req.body.command, { cwd: cs.directory }, (error, stdout, stderr) => {
        res.json({ status: 'executed', command: req.body.command, stdout, stderr, exitCode: error ? error.code : 0 });
    });
});

app.delete('/codespaces/delete/:id', authenticateJWT, (req, res) => {
    let list = readJson(CODESPACES_FILE);
    const cs = list.find(c => c.id === req.params.id);
    if (!cs) return res.status(404).json({ error: 'Codespace not found' });
    if (cs.createdBy !== req.user.username) return res.status(403).json({ error: 'Access denied' });
    try { fs.rmSync(path.join(__dirname, 'codespaces', req.params.id), { recursive: true, force: true }); } catch {}
    list = list.filter(c => c.id !== req.params.id);
    writeJson(CODESPACES_FILE, list);
    activeSessions.delete(req.params.id);
    res.json({ status: 'success', message: 'Deleted' });
});

app.get('/codespaces/terminal/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    res.send(`<!DOCTYPE html><html><head><title>Codespace ${id}</title><style>
    body{background:#121212;color:#00ff66;font-family:monospace;padding:20px;margin:0;}
    #t{background:#000;padding:20px;border-radius:5px;height:70vh;overflow-y:auto;}
    #ci{background:#1e1e1e;color:#00ff66;border:1px solid #333;padding:10px;width:100%;font-family:monospace;}
    .out{color:#fff;margin:5px 0;}.err{color:#f44;}</style></head><body>
    <h2>💻 ${id}</h2><div id="t"></div>
    <div style="display:flex;margin-top:10px;"><span>$&nbsp;</span><input id="ci" autofocus></div>
    <br><a href="/codespaces/menu" style="color:#00ff66;">← Back</a>
    <script>
    const t=document.getElementById('t'),ci=document.getElementById('ci'),id='${id}',token=prompt('Bearer Token:');
    async function run(cmd){try{const r=await fetch('/codespaces/exec/'+id,{method:'POST',
    headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'},
    body:JSON.stringify({command:cmd})});const d=await r.json();
    if(d.stdout){const o=document.createElement('div');o.className='out';o.textContent=d.stdout;t.appendChild(o);}
    if(d.stderr){const e=document.createElement('div');e.className='err';e.textContent=d.stderr;t.appendChild(e);}
    t.scrollTop=t.scrollHeight;}catch(e){console.error(e);}}
    ci.addEventListener('keypress',e=>{if(e.key==='Enter'&&ci.value.trim()){
    const c=ci.value.trim();const p=document.createElement('div');p.className='out';p.textContent='$ '+c;t.appendChild(p);
    run(c);ci.value='';}});
    t.innerHTML='<div class="out">Welcome</div>';</script></body></html>`);
});

// ============ ISSUES ============
app.post('/issues/create', authenticateJWT, (req, res) => {
    try {
        const { repoName, title, description, labels = [] } = req.body;
        if (!repoName || !title) return res.status(400).json({ error: 'repoName and title required' });
        if (!fs.existsSync(path.join(REPO_ROOT, repoName))) return res.status(404).json({ error: 'Repo not found' });
        const issues = readJson(ISSUES_FILE);
        const issue = { id: 'issue_' + randomHex(8), repoName, title,
            description: description || '', labels: Array.isArray(labels) ? labels : [labels],
            createdBy: req.user.username, createdAt: new Date().toISOString(),
            status: 'open', comments: [] };
        issues.push(issue);
        writeJson(ISSUES_FILE, issues);
        res.json({ status: 'success', issue });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/issues/list', authenticateJWT, (req, res) => {
    let issues = readJson(ISSUES_FILE);
    if (req.query.repoName) issues = issues.filter(i => i.repoName === req.query.repoName);
    res.json({ issues });
});

app.get('/issues/:id', authenticateJWT, (req, res) => {
    const issue = readJson(ISSUES_FILE).find(i => i.id === req.params.id);
    if (!issue) return res.status(404).json({ error: 'Issue not found' });
    res.json({ issue });
});

app.put('/issues/:id', authenticateJWT, (req, res) => {
    const issues = readJson(ISSUES_FILE);
    const idx = issues.findIndex(i => i.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Issue not found' });
    if (issues[idx].createdBy !== req.user.username) return res.status(403).json({ error: 'Access denied' });
    const { status, labels, title, description } = req.body;
    if (status) issues[idx].status = status;
    if (labels) issues[idx].labels = labels;
    if (title) issues[idx].title = title;
    if (description) issues[idx].description = description;
    issues[idx].updatedAt = new Date().toISOString();
    writeJson(ISSUES_FILE, issues);
    res.json({ status: 'success', issue: issues[idx] });
});

app.post('/issues/:id/comments', authenticateJWT, (req, res) => {
    const { comment } = req.body;
    if (!comment) return res.status(400).json({ error: 'Comment required' });
    const issues = readJson(ISSUES_FILE);
    const idx = issues.findIndex(i => i.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Issue not found' });
    const c = { id: 'cmt_' + randomHex(8), comment, createdBy: req.user.username, createdAt: new Date().toISOString() };
    issues[idx].comments.push(c);
    writeJson(ISSUES_FILE, issues);
    res.json({ status: 'success', comment: c });
});

// ============ OAUTH APP MANAGEMENT ============
app.post('/api/oauth/apps', authenticateJWT, (req, res) => {
    const { name, redirect_uri } = req.body;
    if (!name) return res.status(400).json({ error: 'application_name_required' });
    const clientId = generateClientId();
    const clientSecret = generateClientSecret();
    const apps = readJson(APPS_FILE);
    apps.push({ id: randomHex(16), name, client_id: clientId, client_secret: clientSecret,
        redirect_uri: redirect_uri || null, created_by: req.user.username, created_at: new Date().toISOString() });
    writeJson(APPS_FILE, apps);
    res.status(201).json({ status: 'success', name, client_id: clientId, client_secret: clientSecret, redirect_uri: redirect_uri || null });
});

app.get('/api/oauth/apps', authenticateJWT, (req, res) => {
    const apps = readJson(APPS_FILE).map(a => ({
        name: a.name, client_id: a.client_id, redirect_uri: a.redirect_uri,
        created_at: a.created_at, created_by: a.created_by
    }));
    res.json({ apps });
});

// ============ OAUTH AUTHORIZE ============
app.get('/oauth/authorize', (req, res) => {
    const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;
    if (!response_type || !client_id || !redirect_uri) return res.status(400).send('Missing parameters');
    const app_ = readJson(APPS_FILE).find(a => a.client_id === client_id);
    if (!app_) return res.status(400).send('Invalid client_id');
    if (app_.redirect_uri && app_.redirect_uri !== redirect_uri) return res.status(400).send('Invalid redirect_uri');

    const authId = randomHex(16);
    const requests = readJson(AUTH_CODES_FILE);
    requests.push({ id: authId, client_id, redirect_uri, scope: scope || 'openid profile email',
        state: state || null, code_challenge: code_challenge || null,
        code_challenge_method: code_challenge_method || 'S256',
        created_at: new Date().toISOString() });
    writeJson(AUTH_CODES_FILE, requests);

    res.send(`<!DOCTYPE html><html><head><title>Authorize</title><style>
    body{font-family:monospace;background:#121212;color:#00ff66;padding:20px;max-width:600px;margin:0 auto;}
    form{background:#1e1e1e;padding:20px;border-radius:5px;}
    input,button{background:#2b2b2b;color:#fff;border:1px solid #444;padding:10px;margin:5px 0;width:100%;font-family:monospace;}
    button{background:#0088cc;cursor:pointer;font-weight:bold;}</style></head><body>
    <h1>🔐 Authorize</h1><p>App: <strong>${app_.name}</strong></p>
    <form action="/oauth/authorize" method="POST">
    <input type="hidden" name="auth_id" value="${authId}">
    <input type="hidden" name="client_id" value="${client_id}">
    <input type="hidden" name="redirect_uri" value="${redirect_uri}">
    <input type="hidden" name="state" value="${state || ''}">
    <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
    <input type="hidden" name="code_challenge_method" value="${code_challenge_method || 'S256'}">
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Authorize</button>
    </form></body></html>`);
});

app.post('/oauth/authorize', (req, res) => {
    const { auth_id, client_id, redirect_uri, state, code_challenge, code_challenge_method, username, password } = req.body;
    const user = readJson(USERS_FILE).find(u => u.username === username);
    if (!user || user.passwordHash !== hashPassword(password || '')) return res.status(401).send('Invalid credentials');
    const code = randomHex(32);
    const codes = readJson(AUTH_CODES_FILE);
    codes.push({ code, client_id, redirect_uri, user_id: user.id, username: user.username,
        state: state || null, code_challenge: code_challenge || null,
        code_challenge_method: code_challenge_method || 'S256',
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 600000).toISOString(), used: false });
    writeJson(AUTH_CODES_FILE, codes.filter(c => c.id !== auth_id));
    res.redirect(`${redirect_uri}?code=${code}${state ? `&state=${state}` : ''}`);
});

app.post('/oauth2/token', (req, res) => {
    const { grant_type, code, client_id, client_secret, redirect_uri, code_verifier } = req.body;
    if (grant_type !== 'authorization_code') return res.status(400).json({ error: 'unsupported_grant_type' });
    const app_ = readJson(APPS_FILE).find(a => a.client_id === client_id);
    if (!app_) return res.status(400).json({ error: 'invalid_client' });
    if (client_secret && app_.client_secret !== client_secret) return res.status(400).json({ error: 'invalid_client' });
    const codes = readJson(AUTH_CODES_FILE);
    const ac = codes.find(a => a.code === code && !a.used);
    if (!ac) return res.status(400).json({ error: 'invalid_grant' });
    if (new Date(ac.expires_at) < new Date()) { ac.used = true; writeJson(AUTH_CODES_FILE, codes); return res.status(400).json({ error: 'invalid_grant' }); }
    if (ac.redirect_uri !== redirect_uri) return res.status(400).json({ error: 'invalid_grant' });
    if (ac.code_challenge) {
        if (!code_verifier) return res.status(400).json({ error: 'invalid_grant' });
        if (generateCodeChallenge(code_verifier, ac.code_challenge_method || 'S256') !== ac.code_challenge) {
            return res.status(400).json({ error: 'invalid_grant' });
        }
    }
    ac.used = true;
    writeJson(AUTH_CODES_FILE, codes);
    const accessToken = jwt.sign({ sub: ac.user_id, username: ac.username, client_id, jti: randomHex(32), scope: 'openid profile email' },
        OAUTH_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ sub: ac.user_id, username: ac.username, client_id, jti: randomHex(32) },
        OAUTH_SECRET, { expiresIn: '7d' });
    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, refresh_token: refreshToken, scope: 'openid profile email' });
});

app.get('/api/pkce/generate', authenticateJWT, (req, res) => {
    const v = generateCodeVerifier();
    res.json({ code_verifier: v, code_challenge: generateCodeChallenge(v), code_challenge_method: 'S256' });
});

app.post('/oauth/device/code', (req, res) => {
    const deviceCode = randomHex(32);
    const userCode = generateDeviceCode();
    const expiresIn = 600;
    deviceCodes.set(deviceCode, { deviceCode, userCode, clientId: req.body.client_id || null,
        username: null, status: 'pending', expiresAt: Date.now() + expiresIn * 1000 });
    res.json({ device_code: deviceCode, user_code: userCode,
        verification_uri: `${baseUrl(req)}/oauth/device`, expires_in: expiresIn });
});

app.get('/oauth/device', (req, res) => res.send(`<h1>Device Login</h1>
<form action="/login/device" method="POST">
<input name="device_code" placeholder="Device Code" required>
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button></form>`));

app.post('/login/device', (req, res) => {
    const { device_code, username, password } = req.body;
    let device = null;
    for (const item of deviceCodes.values()) {
        if (item.deviceCode === device_code || item.userCode === device_code.toUpperCase()) { device = item; break; }
    }
    if (!device || Date.now() > device.expiresAt) return res.status(400).send('Invalid or expired device code');
    const user = readJson(USERS_FILE).find(u => u.username === username);
    if (!user || user.passwordHash !== hashPassword(password)) return res.status(401).send('Invalid credentials');
    device.status = 'approved';
    device.username = username;
    res.send('✅ Device Connected!');
});

app.post('/oauth2/token/device', (req, res) => {
    const device = deviceCodes.get(req.body.device_code);
    if (!device || device.status !== 'approved') return res.status(400).json({ error: 'invalid_device_code' });
    const accessToken = jwt.sign({ sub: device.username, username: device.username, jti: randomHex(32) }, OAUTH_SECRET, { expiresIn: '1h' });
    deviceCodes.delete(req.body.device_code);
    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
});

// ============ AUTH ============
app.post('/api/auth/register', (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'username_and_password_required' });
        const users = readJson(USERS_FILE);
        if (users.some(u => u.username === username)) return res.status(409).json({ error: 'username_already_exists' });
        users.push({ id: randomHex(16), username, passwordHash: hashPassword(password), createdAt: new Date().toISOString() });
        writeJson(USERS_FILE, users);
        res.status(201).json({ status: 'success', message: 'Account created', username });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login', (req, res) => {
    try {
        const { username, password } = req.body;
        const user = readJson(USERS_FILE).find(u => u.username === username);
        if (!user || user.passwordHash !== hashPassword(password || '')) {
            return res.status(401).json({ error: 'invalid_credentials' });
        }
        const accessToken = jwt.sign({ sub: user.id, username: user.username, jti: randomHex(32) }, OAUTH_SECRET, { expiresIn: '1h' });
        res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/me', authenticateJWT, (req, res) => {
    res.json({ authenticated: true, username: req.user.username });
});

// ============ ⭐ NEW: /api/whoami ============
app.get('/api/whoami', authenticateJWT, (req, res) => {
    res.json({
        username: req.user.username,
        sub: req.user.sub,
        client_id: req.user.client_id || null,
        scope: req.user.scope || 'openid profile email',
        token_id: req.user.jti || null,
        issued_at: req.user.iat ? new Date(req.user.iat * 1000).toISOString() : null,
        expires_at: req.user.exp ? new Date(req.user.exp * 1000).toISOString() : null
    });
});

// ============ ⭐ NEW: /api/oauth/status ============
app.get('/api/oauth/status', authenticateJWT, (req, res) => {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = req.user.exp ? Math.max(0, req.user.exp - now) : null;
    const revoked = req.user.jti ? isTokenRevoked(req.user.jti) : false;

    // Count active OAuth apps owned by this user
    const ownedApps = readJson(APPS_FILE).filter(a => a.created_by === req.user.username).length;

    res.json({
        status: 'active',
        authenticated: true,
        user: req.user.username,
        sub: req.user.sub,
        token_id: req.user.jti || null,
        client_id: req.user.client_id || null,
        scope: (req.user.scope || 'openid profile email').split(' '),
        expires_in: expiresIn,
        expires_at: req.user.exp ? new Date(req.user.exp * 1000).toISOString() : null,
        issued_at: req.user.iat ? new Date(req.user.iat * 1000).toISOString() : null,
        revoked: revoked,
        owned_apps: ownedApps,
        server_time: new Date().toISOString()
    });
});

// ============ ⭐ NEW: /api/oauth/userinfo (OIDC-style) ============
// Supports both:
//   1. Bearer token in Authorization header (standard OIDC userinfo)
//   2. ?access_token= query param (per OIDC spec for some clients)
app.get('/api/oauth/userinfo', (req, res) => {
    let token = null;

    // Method 1: Authorization header
    const authorization = req.headers.authorization || '';
    if (authorization.startsWith('Bearer ')) {
        token = authorization.substring(7);
    }

    // Method 2: access_token query parameter
    if (!token && req.query.access_token) {
        token = req.query.access_token;
    }

    if (!token) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="userinfo", error="invalid_token"');
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Bearer token or access_token query parameter required'
        });
    }

    let decoded;
    try {
        decoded = jwt.verify(token, OAUTH_SECRET);
    } catch (err) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="userinfo", error="invalid_token"');
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Token is invalid or expired'
        });
    }

    if (decoded.jti && isTokenRevoked(decoded.jti)) {
        res.setHeader('WWW-Authenticate', 'Bearer realm="userinfo", error="invalid_token"');
        return res.status(401).json({
            error: 'invalid_token',
            error_description: 'Token has been revoked'
        });
    }

    // Look up the user to return current profile fields
    const user = readJson(USERS_FILE).find(u => u.id === decoded.sub || u.username === decoded.username);
    if (!user) {
        return res.status(404).json({
            error: 'user_not_found',
            error_description: 'User record no longer exists'
        });
    }

    // OIDC standard claims
    res.json({
        sub: user.id,
        preferred_username: user.username,
        name: user.username,
        username: user.username,
        email: `${user.username}@localhost`,
        email_verified: false,
        picture: null,
        locale: 'en',
        updated_at: user.createdAt ? Math.floor(new Date(user.createdAt).getTime() / 1000) : undefined,
        // Extra claims
        client_id: decoded.client_id || null,
        scope: decoded.scope || 'openid profile email'
    });
});

// Also accept POST per some OIDC implementations
app.post('/api/oauth/userinfo', (req, res) => {
    req.query.access_token = req.query.access_token || req.body.access_token;
    app._router.handle(
        Object.assign(req, { method: 'GET', url: '/api/oauth/userinfo' + (req.query.access_token ? '?access_token=' + encodeURIComponent(req.query.access_token) : '') }),
        res, () => {}
    );
});

// ============ LOGOUT / HEALTH ============
app.post('/api/auth/logout', authenticateJWT, (req, res) => {
    if (req.user.jti) revokeToken(req.user.jti, req.user.exp);
    res.json({ status: 'success', message: 'Logged out successfully' });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'unified-git-oauth-server', time: new Date().toISOString() });
});

// ============ GIT SMART-HTTP ============
app.all(/^\/repos\/([^\/]+)\.git(.*)$/, authenticateJWT, (req, res) => {
    const repoName = req.params[0];
    const gitPath = req.params[1];
    const repoPath = path.join(REPO_ROOT, repoName);
    if (!fs.existsSync(repoPath)) return res.status(404).send('Git Repository Not Found');

    const backend = spawn(GIT_BACKEND_BIN, [], {
        env: Object.assign({}, process.env, {
            GIT_PROJECT_ROOT: REPO_ROOT,
            GIT_HTTP_EXPORT_ALL: '1',
            PATH_INFO: `/${repoName}${gitPath || ''}`,
            REMOTE_USER: req.user ? req.user.username : 'git-user',
            REQUEST_METHOD: req.method,
            QUERY_STRING: req.url.split('?')[1] || '',
            CONTENT_TYPE: req.headers['content-type'] || ''
        })
    });
    req.pipe(backend.stdin);
    backend.stdout.on('data', (data) => {
        const headEnd = data.indexOf('\r\n\r\n');
        if (headEnd !== -1 && !res.headersSent) {
            const head = data.slice(0, headEnd).toString();
            const body = data.slice(headEnd + 4);
            head.split('\r\n').forEach((line) => {
                const [key, value] = line.split(': ');
                if (key && value) res.setHeader(key, value);
            });
            res.write(body);
        } else res.write(data);
    });
    backend.on('close', () => res.end());
    backend.on('error', (err) => { if (!res.headersSent) res.status(500).send(`Git Backend Error: ${err.message}`); });
});

// Static sites
app.use('/sites/:repoName', optionalAuth, (req, res, next) => {
    const repoPath = path.join(REPO_ROOT, req.params.repoName);
    if (fs.existsSync(repoPath)) express.static(repoPath)(req, res, next);
    else res.status(404).send('Site Not Found');
});

// ============ GLOBAL ERROR HANDLER ============
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: 'internal_server_error', message: err.message, path: req.path });
});

// 404 fallback
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found', message: 'Resource or Site Not Found', path: req.path, method: req.method });
});

// ============ START ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Unified Git & OAuth Server on port ${PORT}`);
    console.log(`📊 Dashboard:      http://localhost:${PORT}/dashboard`);
    console.log(`💻 Codespaces:     http://localhost:${PORT}/codespaces/menu`);
    console.log(`📝 Issues:         http://localhost:${PORT}/issues/menu`);
    console.log(`📦 Releases:       http://localhost:${PORT}/releases/menu`);
    console.log(`🔐 OAuth Apps:     http://localhost:${PORT}/api/oauth/apps`);
    console.log(`🔑 Login:          http://localhost:${PORT}/api/auth/login`);
    console.log(`👤 Whoami:         http://localhost:${PORT}/api/whoami`);
    console.log(`📡 OAuth Status:   http://localhost:${PORT}/api/oauth/status`);
    console.log(`📋 OIDC Userinfo:  http://localhost:${PORT}/api/oauth/userinfo`);
    console.log(`📁 Repo Root:      ${REPO_ROOT}`);
    console.log(`💾 Data Dir:       ${DATA_DIR}`);
});
