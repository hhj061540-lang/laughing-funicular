const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { exec, spawn, execSync } = require('child_process');
const simpleGit = require('simple-git');

const app = express();
const PORT = process.env.PORT || 5900;
const REPO_ROOT = path.join(__dirname, 'repositories');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const APPS_FILE = path.join(DATA_DIR, 'oauth-apps.json');
const SECRET_FILE = path.join(DATA_DIR, 'oauth-secret.key');
const REVOKED_TOKENS_FILE = path.join(DATA_DIR, 'revoked-tokens.json');
const CODESPACES_FILE = path.join(DATA_DIR, 'codespaces.json');
const ISSUES_FILE = path.join(DATA_DIR, 'issues.json');
const AUTH_CODES_FILE = path.join(DATA_DIR, 'auth-codes.json');
const RELEASES_FILE = path.join(DATA_DIR, 'releases.json');
const RELEASE_ASSETS_DIR = path.join(DATA_DIR, 'release-assets');

// Ensure directories exist
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

// OAuth Secret Initialization
let OAUTH_SECRET;
if (fs.existsSync(SECRET_FILE)) {
    OAUTH_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
} else {
    OAUTH_SECRET = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync(SECRET_FILE, OAUTH_SECRET, { mode: 0o600 });
}

const deviceCodes = new Map();
const activeSessions = new Map();

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const { repoName, tagName } = req.params;
        const assetDir = path.join(RELEASE_ASSETS_DIR, repoName, tagName);
        fs.mkdirSync(assetDir, { recursive: true });
        cb(null, assetDir);
    },
    filename: (req, file, cb) => {
        // Sanitize filename
        const sanitized = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, sanitized);
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

// Helper Functions
function readJson(file) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return []; }
}
function writeJson(file, value) {
    fs.writeFileSync(file, JSON.stringify(value, null, 2));
}
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

// PKCE Helper Functions
function generateCodeChallenge(codeVerifier, method = 'S256') {
    if (method === 'S256') {
        return crypto.createHash('sha256').update(codeVerifier).digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
    return codeVerifier;
}

function generateCodeVerifier() {
    return randomHex(32);
}

// Locate git-http-backend
function getGitBackendPath() {
    const standardPaths = [
        '/usr/lib/git-core/git-http-backend',
        '/usr/libexec/git-core/git-http-backend',
        '/usr/local/libexec/git-core/git-http-backend'
    ];
    for (const p of standardPaths) {
        if (fs.existsSync(p)) return p;
    }
    try {
        const gitExecPath = execSync('git --exec-path').toString().trim();
        const backendPath = path.join(gitExecPath, 'git-http-backend');
        if (fs.existsSync(backendPath)) return backendPath;
    } catch (e) {}
    return 'git-http-backend';
}
const GIT_BACKEND_BIN = getGitBackendPath();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// JWT Authentication Middleware
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

// Optional authentication (for public release downloads)
function optionalAuth(req, res, next) {
    const authorization = req.headers.authorization || '';
    if (authorization.startsWith('Bearer ')) {
        const token = authorization.substring(7);
        try {
            const decoded = jwt.verify(token, OAUTH_SECRET);
            req.user = decoded;
        } catch (error) {
            // Ignore invalid tokens for optional auth
        }
    }
    next();
}

// Dashboard UI
const htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <title>Unified Git & OAuth Pipeline Manager</title>
    <style>
        body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; }
        h1, h2, h3 { border-bottom: 1px solid #333; padding-bottom: 5px; }
        .menu { background: #1e1e1e; padding: 10px; border-radius: 5px; margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
        .menu a { color: #00ff66; text-decoration: none; padding: 8px 15px; background: #2b2b2b; border-radius: 3px; border: 1px solid #444; }
        .menu a:hover { background: #0088cc; }
        form { margin-bottom: 15px; background: #1e1e1e; padding: 15px; border-radius: 5px; }
        input, textarea, select, button { background: #2b2b2b; color: #fff; border: 1px solid #444; padding: 8px; margin: 4px 0; width: 98%; font-family: monospace; }
        button { cursor: pointer; background: #0088cc; font-weight: bold; }
        button:hover { background: #00aaff; }
        pre { background: #000; padding: 10px; border: 1px solid #333; overflow-x: auto; color: #fff; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .code-box { background: #000; color: #00ff66; padding: 10px; border: 1px solid #00ff66; font-size: 14px; user-select: all; word-break: break-all; }
        .section { background: #1a1a1a; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .success { color: #00ff66; }
        .error { color: #ff4444; }
    </style>
</head>
<body>
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

    <p>Environment: Standalone Express Server | Port: ${PORT}</p>

    <div class="grid">
        <div class="section">
            <h2>📁 1. Create Repository</h2>
            <form action="/create-repo" method="POST">
                <input type="text" name="repoName" placeholder="Repository Name" required>
                <button type="submit">Create Repository</button>
            </form>
        </div>
        <div class="section">
            <h2>🔗 2. Get Clone URL</h2>
            <form action="/get-clone-url" method="GET">
                <input type="text" name="repoName" placeholder="Repository Name" required>
                <button type="submit">Generate Commands</button>
            </form>
        </div>
        <div class="section">
            <h2>📄 3. Create Pipeline File</h2>
            <form action="/create-yml" method="POST">
                <input type="text" name="repoName" placeholder="Repository Name" required>
                <input type="text" name="ymlFileName" placeholder="File Name (e.g., pipeline.yml)" required>
                <textarea name="ymlContents" rows="4" placeholder="YAML Contents"></textarea>
                <button type="submit">Save & Commit .yml File</button>
            </form>
        </div>
        <div class="section">
            <h2>🏷️ 4. Create Release & Tag</h2>
            <form action="/create-release" method="POST">
                <input type="text" name="repoName" placeholder="Repository Name" required>
                <input type="text" name="tagName" placeholder="Tag Name (e.g., v1.0.0)" required>
                <input type="text" name="releaseName" placeholder="Release Name (optional)">
                <textarea name="releaseBody" rows="3" placeholder="Release Notes (optional)"></textarea>
                <button type="submit">Create Release</button>
            </form>
        </div>
        <div class="section">
            <h2>🌿 5. Branching & Logs</h2>
            <form action="/create-branch" method="POST">
                <input type="text" name="repoName" placeholder="Repository Name" required>
                <input type="text" name="branchName" placeholder="Branch Name" required>
                <button type="submit">Create Branch</button>
            </form>
            <form action="/logs" method="GET" style="margin-top: 10px;">
                <input type="text" name="repoName" placeholder="Repository Name" required>
                <button type="submit">View Commit History</button>
            </form>
        </div>
        <div class="section">
            <h2>⚙️ 6. Pipeline Runner</h2>
            <form action="/run-pipeline" method="POST">
                <input type="text" name="repoName" placeholder="Repository Name" required>
                <input type="text" name="pipelineFile" placeholder="Pipeline File (e.g., pipeline.yml)" required>
                <button type="submit">Run Pipeline</button>
            </form>
            <form action="/pipeline-logs" method="GET" style="margin-top: 10px;">
                <input type="text" name="repoName" placeholder="Repository Name" required>
                <button type="submit">Fetch Pipeline Logs</button>
            </form>
        </div>
    </div>

    <h2>📋 Repository List</h2>
    <button onclick="fetchRepos()">Fetch All Repositories</button>
    <pre id="repoOutput"></pre>

    <script>
        function fetchRepos() {
            const token = prompt('Enter Bearer Token:');
            fetch('/api/list-repos', {
                headers: { 'Authorization': 'Bearer ' + token }
            })
            .then(res => res.json())
            .then(data => document.getElementById('repoOutput').textContent = JSON.stringify(data, null, 2))
            .catch(err => document.getElementById('repoOutput').textContent = 'Error: ' + err);
        }
    </script>
</body>
</html>
`;

// ============ DASHBOARD ROUTES ============
app.get('/dashboard', (req, res) => res.send(htmlContent));
app.get('/', (req, res) => res.send(htmlContent));

// ============ RELEASES MENU ============
app.get('/releases/menu', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Release Manager</title>
            <style>
                body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; }
                h1 { border-bottom: 1px solid #333; padding-bottom: 5px; }
                .menu { background: #1e1e1e; padding: 10px; border-radius: 5px; margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
                .menu a { color: #00ff66; text-decoration: none; padding: 8px 15px; background: #2b2b2b; border-radius: 3px; border: 1px solid #444; }
                .menu a:hover { background: #0088cc; }
                form { background: #1e1e1e; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
                input, textarea, button { background: #2b2b2b; color: #fff; border: 1px solid #444; padding: 8px; margin: 4px 0; width: 98%; font-family: monospace; }
                button { cursor: pointer; background: #0088cc; font-weight: bold; }
                button:hover { background: #00aaff; }
                .release-item { background: #1a1a1a; border: 1px solid #333; padding: 15px; margin: 10px 0; border-radius: 5px; }
                .release-item h3 { margin-top: 0; color: #00ff66; }
                .asset { background: #000; padding: 8px; margin: 5px 0; border-radius: 3px; display: flex; justify-content: space-between; align-items: center; }
                .asset a { color: #00ff66; text-decoration: none; }
                .asset a:hover { text-decoration: underline; }
                .upload-form { background: #252525; padding: 10px; margin-top: 10px; border-radius: 3px; }
                .upload-form input[type="file"] { padding: 5px; }
                .tag { background: #0088cc; padding: 3px 8px; border-radius: 3px; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="menu">
                <a href="/dashboard">🏠 Home</a>
                <a href="/releases/menu">📦 Releases</a>
                <a href="/codespaces/menu">💻 Codespaces</a>
                <a href="/issues/menu">📝 Issues</a>
            </div>
            
            <h1>📦 Release Manager</h1>
            
            <h2>Create Release</h2>
            <form id="createReleaseForm">
                <input type="text" id="repoName" placeholder="Repository Name" required>
                <input type="text" id="tagName" placeholder="Tag Name (e.g., v1.0.0)" required>
                <input type="text" id="releaseName" placeholder="Release Name (optional)">
                <textarea id="releaseBody" rows="3" placeholder="Release Notes (optional)"></textarea>
                <input type="text" id="token" placeholder="Bearer Token" required>
                <button type="submit">Create Release</button>
            </form>

            <h2>Upload Release Asset</h2>
            <form id="uploadForm" enctype="multipart/form-data">
                <input type="text" id="uploadRepo" placeholder="Repository Name" required>
                <input type="text" id="uploadTag" placeholder="Tag Name" required>
                <input type="file" id="assetFile" required>
                <input type="text" id="uploadToken" placeholder="Bearer Token" required>
                <button type="submit">Upload Asset</button>
            </form>
            
            <h2>Existing Releases</h2>
            <button onclick="listReleases()">Refresh Releases</button>
            <div id="releasesList"></div>

            <script>
                async function createRelease(e) {
                    e.preventDefault();
                    const repoName = document.getElementById('repoName').value;
                    const tagName = document.getElementById('tagName').value;
                    const releaseName = document.getElementById('releaseName').value;
                    const releaseBody = document.getElementById('releaseBody').value;
                    const token = document.getElementById('token').value;
                    
                    try {
                        const response = await fetch('/api/releases/create', {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + token,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ repoName, tagName, releaseName, releaseBody })
                        });
                        const data = await response.json();
                        alert(JSON.stringify(data, null, 2));
                        listReleases();
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }

                async function uploadAsset(e) {
                    e.preventDefault();
                    const repoName = document.getElementById('uploadRepo').value;
                    const tagName = document.getElementById('uploadTag').value;
                    const file = document.getElementById('assetFile').files[0];
                    const token = document.getElementById('uploadToken').value;
                    
                    if (!file) {
                        alert('Please select a file');
                        return;
                    }

                    const formData = new FormData();
                    formData.append('asset', file);
                    
                    try {
                        const response = await fetch('/api/releases/' + repoName + '/' + tagName + '/assets', {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + token
                            },
                            body: formData
                        });
                        const data = await response.json();
                        alert(JSON.stringify(data, null, 2));
                        listReleases();
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }

                async function listReleases() {
                    try {
                        const response = await fetch('/api/releases/list');
                        const data = await response.json();
                        const container = document.getElementById('releasesList');
                        
                        if (!data.releases || data.releases.length === 0) {
                            container.innerHTML = '<p>No releases found</p>';
                            return;
                        }

                        let html = '';
                        data.releases.forEach(release => {
                            html += '<div class="release-item">';
                            html += '<h3>' + (release.releaseName || release.tagName) + ' <span class="tag">' + release.tagName + '</span></h3>';
                            html += '<p><strong>Repository:</strong> ' + release.repoName + '</p>';
                            html += '<p><strong>Created:</strong> ' + release.createdAt + '</p>';
                            if (release.releaseBody) {
                                html += '<p><strong>Notes:</strong> ' + release.releaseBody + '</p>';
                            }
                            
                            if (release.assets && release.assets.length > 0) {
                                html += '<h4>Assets:</h4>';
                                release.assets.forEach(asset => {
                                    html += '<div class="asset">';
                                    html += '<span>' + asset.name + ' (' + (asset.size / 1024).toFixed(2) + ' KB)</span>';
                                    html += '<a href="' + asset.downloadUrl + '" download>⬇️ Download</a>';
                                    html += '</div>';
                                });
                            } else {
                                html += '<p><em>No assets uploaded yet</em></p>';
                            }
                            
                            html += '<div class="upload-form">';
                            html += '<strong>Upload Asset:</strong><br>';
                            html += '<input type="file" id="file_' + release.tagName + '">';
                            html += '<button onclick="quickUpload(\'' + release.repoName + '\', \'' + release.tagName + '\')">Upload</button>';
                            html += '</div>';
                            
                            html += '</div>';
                        });
                        container.innerHTML = html;
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }

                async function quickUpload(repoName, tagName) {
                    const fileInput = document.getElementById('file_' + tagName);
                    const token = prompt('Enter Bearer Token:');
                    if (!token || !fileInput.files[0]) {
                        alert('Token and file required');
                        return;
                    }

                    const formData = new FormData();
                    formData.append('asset', fileInput.files[0]);
                    
                    try {
                        const response = await fetch('/api/releases/' + repoName + '/' + tagName + '/assets', {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + token
                            },
                            body: formData
                        });
                        const data = await response.json();
                        alert(JSON.stringify(data, null, 2));
                        listReleases();
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }

                document.getElementById('createReleaseForm').addEventListener('submit', createRelease);
                document.getElementById('uploadForm').addEventListener('submit', uploadAsset);
                
                // Load releases on page load
                listReleases();
            </script>
        </body>
        </html>
    `);
});

// ============ CODESPACE MENU ============
app.get('/codespaces/menu', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Codespace Manager</title>
            <style>
                body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; }
                h1 { border-bottom: 1px solid #333; padding-bottom: 5px; }
                .menu { background: #1e1e1e; padding: 10px; border-radius: 5px; margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
                .menu a { color: #00ff66; text-decoration: none; padding: 8px 15px; background: #2b2b2b; border-radius: 3px; border: 1px solid #444; }
                .menu a:hover { background: #0088cc; }
                form { background: #1e1e1e; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
                input, button { background: #2b2b2b; color: #fff; border: 1px solid #444; padding: 8px; margin: 4px 0; width: 98%; font-family: monospace; }
                button { cursor: pointer; background: #0088cc; font-weight: bold; }
                button:hover { background: #00aaff; }
                .codespace-list { background: #1a1a1a; padding: 10px; border-radius: 5px; }
                .codespace-item { border: 1px solid #333; padding: 10px; margin: 5px 0; }
            </style>
        </head>
        <body>
            <div class="menu">
                <a href="/dashboard">🏠 Home</a>
                <a href="/codespaces/menu">💻 Codespaces</a>
                <a href="/issues/menu">📝 Issues</a>
                <a href="/releases/menu">📦 Releases</a>
            </div>
            
            <h1>💻 Codespace Manager</h1>
            
            <h2>Create Codespace</h2>
            <form id="createForm">
                <input type="text" id="repoName" placeholder="Repository Name" required>
                <input type="text" id="branch" placeholder="Branch (default: main)" value="main">
                <input type="text" id="machine" placeholder="Machine Type (basic/standard/advanced)" value="basic">
                <input type="text" id="token" placeholder="Bearer Token" required>
                <button type="submit">Create Codespace</button>
            </form>
            
            <h2>Your Codespaces</h2>
            <div id="codespaceList" class="codespace-list">
                <button onclick="listCodespaces()">Refresh List</button>
                <div id="codespaces"></div>
            </div>

            <h2>Quick Actions</h2>
            <button onclick="openTerminal()">Open Terminal</button>

            <script>
                async function createCodespace(e) {
                    e.preventDefault();
                    const repoName = document.getElementById('repoName').value;
                    const branch = document.getElementById('branch').value || 'main';
                    const machine = document.getElementById('machine').value || 'basic';
                    const token = document.getElementById('token').value;
                    
                    try {
                        const response = await fetch('/codespaces/create', {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + token,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ repoName, branch, machine })
                        });
                        const data = await response.json();
                        alert(JSON.stringify(data, null, 2));
                        listCodespaces();
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }

                async function listCodespaces() {
                    const token = prompt('Enter Bearer Token:');
                    if (!token) return;
                    
                    try {
                        const response = await fetch('/codespaces/list', {
                            headers: { 'Authorization': 'Bearer ' + token }
                        });
                        const data = await response.json();
                        const container = document.getElementById('codespaces');
                        container.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }

                function openTerminal() {
                    const id = prompt('Enter Codespace ID:');
                    if (id) {
                        window.open('/codespaces/terminal/' + id, '_blank');
                    }
                }

                document.getElementById('createForm').addEventListener('submit', createCodespace);
            </script>
        </body>
        </html>
    `);
});

// ============ ISSUES MENU ============
app.get('/issues/menu', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Issue Tracker</title>
            <style>
                body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; }
                h1 { border-bottom: 1px solid #333; padding-bottom: 5px; }
                .menu { background: #1e1e1e; padding: 10px; border-radius: 5px; margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
                .menu a { color: #00ff66; text-decoration: none; padding: 8px 15px; background: #2b2b2b; border-radius: 3px; border: 1px solid #444; }
                .menu a:hover { background: #0088cc; }
                form { background: #1e1e1e; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
                input, textarea, button { background: #2b2b2b; color: #fff; border: 1px solid #444; padding: 8px; margin: 4px 0; width: 98%; font-family: monospace; }
                button { cursor: pointer; background: #0088cc; font-weight: bold; }
                button:hover { background: #00aaff; }
            </style>
        </head>
        <body>
            <div class="menu">
                <a href="/dashboard">🏠 Home</a>
                <a href="/codespaces/menu">💻 Codespaces</a>
                <a href="/issues/menu">📝 Issues</a>
                <a href="/releases/menu">📦 Releases</a>
            </div>
            
            <h1>📝 Issue Tracker</h1>
            
            <h2>Create Issue</h2>
            <form id="createIssueForm">
                <input type="text" id="issueRepo" placeholder="Repository Name" required>
                <input type="text" id="issueTitle" placeholder="Issue Title" required>
                <textarea id="issueDescription" rows="4" placeholder="Description"></textarea>
                <input type="text" id="issueLabels" placeholder="Labels (comma separated)">
                <input type="text" id="issueToken" placeholder="Bearer Token" required>
                <button type="submit">Create Issue</button>
            </form>
            
            <h2>List Issues</h2>
            <button onclick="listIssues()">Refresh Issues</button>
            <pre id="issuesOutput"></pre>

            <script>
                async function createIssue(e) {
                    e.preventDefault();
                    const repoName = document.getElementById('issueRepo').value;
                    const title = document.getElementById('issueTitle').value;
                    const description = document.getElementById('issueDescription').value;
                    const labels = document.getElementById('issueLabels').value.split(',').filter(l => l.trim());
                    const token = document.getElementById('issueToken').value;
                    
                    try {
                        const response = await fetch('/issues/create', {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + token,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ repoName, title, description, labels })
                        });
                        const data = await response.json();
                        alert(JSON.stringify(data, null, 2));
                        listIssues();
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }

                async function listIssues() {
                    const token = prompt('Enter Bearer Token:');
                    if (!token) return;
                    
                    try {
                        const response = await fetch('/issues/list', {
                            headers: { 'Authorization': 'Bearer ' + token }
                        });
                        const data = await response.json();
                        document.getElementById('issuesOutput').textContent = JSON.stringify(data, null, 2);
                    } catch (err) {
                        alert('Error: ' + err.message);
                    }
                }

                document.getElementById('createIssueForm').addEventListener('submit', createIssue);
            </script>
        </body>
        </html>
    `);
});

// ============ RELEASE API ENDPOINTS ============

// Create a new release
app.post('/api/releases/create', authenticateJWT, async (req, res) => {
    const { repoName, tagName, releaseName, releaseBody } = req.body;

    if (!repoName || !tagName) {
        return res.status(400).json({ error: 'repoName and tagName are required' });
    }

    const repoPath = path.join(REPO_ROOT, repoName);
    if (!fs.existsSync(repoPath)) {
        return res.status(404).json({ error: 'Repository not found' });
    }

    try {
        const git = simpleGit(repoPath);
        
        // Check if tag already exists
        const tags = await git.tags();
        if (!tags.all.includes(tagName)) {
            // Create the tag
            await git.addTag(tagName);
        }

        // Create release record
        const releases = readJson(RELEASES_FILE);
        const existingRelease = releases.find(r => r.repoName === repoName && r.tagName === tagName);
        
        if (existingRelease) {
            return res.status(409).json({ error: 'Release already exists for this tag' });
        }

        const release = {
            id: 'rel_' + randomHex(16),
            repoName,
            tagName,
            releaseName: releaseName || tagName,
            releaseBody: releaseBody || '',
            createdBy: req.user.username,
            createdAt: new Date().toISOString(),
            assets: [],
            downloadUrl: `${baseUrl(req)}/releases/download/${repoName}/${tagName}`,
            htmlUrl: `${baseUrl(req)}/releases/${repoName}/tag/${tagName}`
        };

        releases.push(release);
        writeJson(RELEASES_FILE, releases);

        // Create asset directory
        const assetDir = path.join(RELEASE_ASSETS_DIR, repoName, tagName);
        fs.mkdirSync(assetDir, { recursive: true });

        res.status(201).json({
            status: 'success',
            message: 'Release created successfully',
            release
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create release', details: err.message });
    }
});

// List all releases
app.get('/api/releases/list', (req, res) => {
    const releases = readJson(RELEASES_FILE);
    
    // Add download URLs to assets
    const releasesWithUrls = releases.map(release => ({
        ...release,
        assets: release.assets.map(asset => ({
            ...asset,
            downloadUrl: `${baseUrl(req)}/releases/download/${release.repoName}/${release.tagName}/${asset.name}`
        }))
    }));

    res.json({ releases: releasesWithUrls });
});

// List releases for a specific repository
app.get('/api/releases/:repoName', (req, res) => {
    const { repoName } = req.params;
    const releases = readJson(RELEASES_FILE);
    const repoReleases = releases.filter(r => r.repoName === repoName);
    
    const releasesWithUrls = repoReleases.map(release => ({
        ...release,
        assets: release.assets.map(asset => ({
            ...asset,
            downloadUrl: `${baseUrl(req)}/releases/download/${release.repoName}/${release.tagName}/${asset.name}`
        }))
    }));

    res.json({ releases: releasesWithUrls });
});

// Get a specific release
app.get('/api/releases/:repoName/:tagName', (req, res) => {
    const { repoName, tagName } = req.params;
    const releases = readJson(RELEASES_FILE);
    const release = releases.find(r => r.repoName === repoName && r.tagName === tagName);
    
    if (!release) {
        return res.status(404).json({ error: 'Release not found' });
    }

    const releaseWithUrls = {
        ...release,
        assets: release.assets.map(asset => ({
            ...asset,
            downloadUrl: `${baseUrl(req)}/releases/download/${release.repoName}/${release.tagName}/${asset.name}`
        }))
    };

    res.json({ release: releaseWithUrls });
});

// Upload asset to a release
app.post('/api/releases/:repoName/:tagName/assets', authenticateJWT, upload.single('asset'), (req, res) => {
    const { repoName, tagName } = req.params;
    
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const releases = readJson(RELEASES_FILE);
    const releaseIndex = releases.findIndex(r => r.repoName === repoName && r.tagName === tagName);
    
    if (releaseIndex === -1) {
        // Remove uploaded file if release doesn't exist
        fs.unlinkSync(req.file.path);
        return res.status(404).json({ error: 'Release not found' });
    }

    // Check if asset already exists
    const existingAsset = releases[releaseIndex].assets.find(a => a.name === req.file.originalname);
    if (existingAsset) {
        // Update existing asset
        existingAsset.size = req.file.size;
        existingAsset.uploadedAt = new Date().toISOString();
        existingAsset.uploadedBy = req.user.username;
    } else {
        // Add new asset
        releases[releaseIndex].assets.push({
            id: 'asset_' + randomHex(8),
            name: req.file.originalname,
            filename: req.file.filename,
            size: req.file.size,
            mimeType: req.file.mimetype,
            uploadedAt: new Date().toISOString(),
            uploadedBy: req.user.username
        });
    }

    releases[releaseIndex].updatedAt = new Date().toISOString();
    writeJson(RELEASES_FILE, releases);

    const asset = releases[releaseIndex].assets.find(a => a.name === req.file.originalname);

    res.status(201).json({
        status: 'success',
        message: 'Asset uploaded successfully',
        asset: {
            ...asset,
            downloadUrl: `${baseUrl(req)}/releases/download/${repoName}/${tagName}/${asset.name}`
        }
    });
});

// Delete an asset from a release
app.delete('/api/releases/:repoName/:tagName/assets/:assetName', authenticateJWT, (req, res) => {
    const { repoName, tagName, assetName } = req.params;
    
    const releases = readJson(RELEASES_FILE);
    const releaseIndex = releases.findIndex(r => r.repoName === repoName && r.tagName === tagName);
    
    if (releaseIndex === -1) {
        return res.status(404).json({ error: 'Release not found' });
    }

    const assetIndex = releases[releaseIndex].assets.findIndex(a => a.name === assetName);
    if (assetIndex === -1) {
        return res.status(404).json({ error: 'Asset not found' });
    }

    // Delete file from disk
    const assetPath = path.join(RELEASE_ASSETS_DIR, repoName, tagName, releases[releaseIndex].assets[assetIndex].filename);
    if (fs.existsSync(assetPath)) {
        fs.unlinkSync(assetPath);
    }

    releases[releaseIndex].assets.splice(assetIndex, 1);
    writeJson(RELEASES_FILE, releases);

    res.json({ status: 'success', message: 'Asset deleted' });
});

// Delete a release
app.delete('/api/releases/:repoName/:tagName', authenticateJWT, async (req, res) => {
    const { repoName, tagName } = req.params;
    
    const releases = readJson(RELEASES_FILE);
    const releaseIndex = releases.findIndex(r => r.repoName === repoName && r.tagName === tagName);
    
    if (releaseIndex === -1) {
        return res.status(404).json({ error: 'Release not found' });
    }

    // Check ownership
    if (releases[releaseIndex].createdBy !== req.user.username) {
        return res.status(403).json({ error: 'Access denied' });
    }

    // Delete assets directory
    const assetDir = path.join(RELEASE_ASSETS_DIR, repoName, tagName);
    if (fs.existsSync(assetDir)) {
        fs.rmSync(assetDir, { recursive: true, force: true });
    }

    // Remove git tag
    try {
        const repoPath = path.join(REPO_ROOT, repoName);
        if (fs.existsSync(repoPath)) {
            const git = simpleGit(repoPath);
            await git.tag(['-d', tagName]);
        }
    } catch (err) {
        console.error('Failed to delete git tag:', err);
    }

    releases.splice(releaseIndex, 1);
    writeJson(RELEASES_FILE, releases);

    res.json({ status: 'success', message: 'Release deleted' });
});

// ============ PUBLIC RELEASE DOWNLOAD ENDPOINTS ============

// Download release asset (public, no auth required)
app.get('/releases/download/:repoName/:tagName/:assetName', optionalAuth, (req, res) => {
    const { repoName, tagName, assetName } = req.params;
    
    // Sanitize inputs to prevent directory traversal
    const sanitizedRepo = repoName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const sanitizedTag = tagName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const sanitizedAsset = assetName.replace(/[^a-zA-Z0-9._-]/g, '_');

    const releases = readJson(RELEASES_FILE);
    const release = releases.find(r => r.repoName === sanitizedRepo && r.tagName === sanitizedTag);
    
    if (!release) {
        return res.status(404).json({ error: 'Release not found' });
    }

    const asset = release.assets.find(a => a.name === assetName);
    if (!asset) {
        return res.status(404).json({ error: 'Asset not found' });
    }

    const assetPath = path.join(RELEASE_ASSETS_DIR, sanitizedRepo, sanitizedTag, asset.filename);
    
    if (!fs.existsSync(assetPath)) {
        return res.status(404).json({ error: 'Asset file not found on disk' });
    }

    // Track download count
    asset.downloadCount = (asset.downloadCount || 0) + 1;
    asset.lastDownloadedAt = new Date().toISOString();
    writeJson(RELEASES_FILE, releases);

    // Set headers for download
    res.setHeader('Content-Disposition', `attachment; filename="${asset.name}"`);
    res.setHeader('Content-Type', asset.mimeType || 'application/octet-stream');
    res.setHeader('Content-Length', asset.size);

    // Stream the file
    const fileStream = fs.createReadStream(assetPath);
    fileStream.pipe(res);
});

// Download entire release as tarball
app.get('/releases/download/:repoName/:tagName', optionalAuth, async (req, res) => {
    const { repoName, tagName } = req.params;
    
    const releases = readJson(RELEASES_FILE);
    const release = releases.find(r => r.repoName === repoName && r.tagName === tagName);
    
    if (!release) {
        return res.status(404).json({ error: 'Release not found' });
    }

    // Create a temporary tarball of the repository at the tag
    const repoPath = path.join(REPO_ROOT, repoName);
    const tempDir = path.join(DATA_DIR, 'temp');
    fs.mkdirSync(tempDir, { recursive: true });
    
    const tarballName = `${repoName}-${tagName}.tar.gz`;
    const tarballPath = path.join(tempDir, tarballName);

    try {
        // Create archive from git repository
        execSync(`cd "${repoPath}" && git archive --format=tar.gz --output="${tarballPath}" ${tagName}`, {
            timeout: 30000
        });

        res.setHeader('Content-Disposition', `attachment; filename="${tarballName}"`);
        res.setHeader('Content-Type', 'application/gzip');

        const fileStream = fs.createReadStream(tarballPath);
        fileStream.pipe(res);

        // Clean up after streaming
        fileStream.on('end', () => {
            try { fs.unlinkSync(tarballPath); } catch (e) {}
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create release archive', details: err.message });
    }
});

// View release page (public)
app.get('/releases/:repoName/tag/:tagName', optionalAuth, (req, res) => {
    const { repoName, tagName } = req.params;
    
    const releases = readJson(RELEASES_FILE);
    const release = releases.find(r => r.repoName === repoName && r.tagName === tagName);
    
    if (!release) {
        return res.status(404).send('<h1>Release not found</h1>');
    }

    const base = baseUrl(req);

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>${release.releaseName || release.tagName} - ${release.repoName}</title>
            <style>
                body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; max-width: 900px; margin: 0 auto; }
                h1 { border-bottom: 1px solid #333; padding-bottom: 10px; }
                .menu { background: #1e1e1e; padding: 10px; border-radius: 5px; margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
                .menu a { color: #00ff66; text-decoration: none; padding: 8px 15px; background: #2b2b2b; border-radius: 3px; border: 1px solid #444; }
                .menu a:hover { background: #0088cc; }
                .release-info { background: #1a1a1a; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                .tag { background: #0088cc; padding: 3px 10px; border-radius: 3px; font-size: 14px; }
                .asset { background: #000; padding: 12px; margin: 8px 0; border-radius: 3px; display: flex; justify-content: space-between; align-items: center; border: 1px solid #333; }
                .asset a { color: #00ff66; text-decoration: none; font-weight: bold; }
                .asset a:hover { text-decoration: underline; }
                .download-btn { background: #00aa44; color: #fff !important; padding: 8px 16px; border-radius: 3px; text-decoration: none !important; }
                .download-btn:hover { background: #00cc55 !important; }
                .meta { color: #888; font-size: 12px; margin-top: 5px; }
            </style>
        </head>
        <body>
            <div class="menu">
                <a href="/dashboard">🏠 Home</a>
                <a href="/releases/menu">📦 Releases</a>
            </div>

            <h1>📦 ${release.releaseName || release.tagName}</h1>
            
            <div class="release-info">
                <p><strong>Repository:</strong> <a href="${base}/sites/${release.repoName}" style="color: #00ff66;">${release.repoName}</a></p>
                <p><strong>Tag:</strong> <span class="tag">${release.tagName}</span></p>
                <p><strong>Created:</strong> ${release.createdAt}</p>
                <p><strong>Created by:</strong> ${release.createdBy}</p>
                ${release.releaseBody ? `<p><strong>Release Notes:</strong></p><pre style="background: #000; padding: 10px; border-radius: 3px; white-space: pre-wrap;">${release.releaseBody}</pre>` : ''}
                
                <p style="margin-top: 15px;">
                    <a href="${base}/releases/download/${release.repoName}/${release.tagName}" class="download-btn" download>
                        ⬇️ Download Source Code (tar.gz)
                    </a>
                </p>
            </div>

            <h2>📎 Release Assets</h2>
            ${release.assets.length > 0 ? release.assets.map(asset => `
                <div class="asset">
                    <div>
                        <strong>${asset.name}</strong>
                        <div class="meta">
                            Size: ${(asset.size / 1024).toFixed(2)} KB | 
                            Uploaded: ${asset.uploadedAt} | 
                            Downloads: ${asset.downloadCount || 0}
                        </div>
                    </div>
                    <a href="${base}/releases/download/${release.repoName}/${release.tagName}/${asset.name}" class="download-btn" download>⬇️ Download</a>
                </div>
            `).join('') : '<p><em>No assets uploaded for this release</em></p>'}
        </body>
        </html>
    `);
});

// Legacy release endpoint (redirects to new format)
app.post('/create-release', authenticateJWT, async (req, res) => {
    const { repoName, tagName } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    
    if (!fs.existsSync(repoPath)) {
        return res.status(404).send('Repository not found.');
    }

    try {
        const git = simpleGit(repoPath);
        await git.addTag(tagName);
        const host = req.get('host');
        const releaseUrl = `https://${host}/releases/${repoName}/tag/${tagName}`;
        const downloadUrl = `https://${host}/releases/download/${repoName}/${tagName}`;
        res.send(`
            <h2>✅ Release Tag Created Successfully!</h2>
            <p>Tag Name: <strong>${tagName}</strong></p>
            <p>Repository: <strong>${repoName}</strong></p>
            <p>Release URL:</p>
            <div class="code-box"><a href="${releaseUrl}" style="color: #00ff66;">${releaseUrl}</a></div>
            <p>Download Source URL:</p>
            <div class="code-box"><a href="${downloadUrl}" style="color: #00ff66;">${downloadUrl}</a></div>
            <br/><a href="/dashboard" style="color: #00ff66;">← Back to Dashboard</a>
        `);
    } catch (err) {
        res.status(500).send(`Error creating tag: ${err.message}`);
    }
});

// ============ CODESPACES ENDPOINTS ============
app.post('/codespaces/create', authenticateJWT, async (req, res) => {
    const { repoName, branch = 'main', machine = 'basic' } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    
    if (!fs.existsSync(repoPath)) {
        return res.status(404).json({ error: 'Repository not found' });
    }

    const codespaceId = 'cs_' + randomHex(16);
    const codespaceDir = path.join(__dirname, 'codespaces', codespaceId);
    fs.mkdirSync(codespaceDir, { recursive: true });

    try {
        const git = simpleGit();
        await git.clone(repoPath, codespaceDir);
        const codespaceGit = simpleGit(codespaceDir);
        await codespaceGit.checkout(branch);
    } catch (err) {
        return res.status(500).json({ error: 'Failed to create codespace', details: err.message });
    }

    const codespace = {
        id: codespaceId,
        repoName,
        branch,
        machine,
        status: 'running',
        createdBy: req.user.username,
        createdAt: new Date().toISOString(),
        directory: codespaceDir
    };

    const codespaces = readJson(CODESPACES_FILE);
    codespaces.push(codespace);
    writeJson(CODESPACES_FILE, codespaces);
    activeSessions.set(codespaceId, codespace);

    res.json({
        status: 'success',
        codespace: {
            id: codespace.id,
            repoName: codespace.repoName,
            branch: codespace.branch,
            status: codespace.status,
            url: `${baseUrl(req)}/codespaces/terminal/${codespaceId}`
        }
    });
});

app.get('/codespaces/list', authenticateJWT, (req, res) => {
    const codespaces = readJson(CODESPACES_FILE);
    const userCodespaces = codespaces.filter(cs => cs.createdBy === req.user.username);
    res.json({ codespaces: userCodespaces });
});

app.post('/codespaces/start/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const codespaces = readJson(CODESPACES_FILE);
    const codespace = codespaces.find(cs => cs.id === id);
    
    if (!codespace) {
        return res.status(404).json({ error: 'Codespace not found' });
    }

    if (codespace.createdBy !== req.user.username) {
        return res.status(403).json({ error: 'Access denied' });
    }

    codespace.status = 'running';
    writeJson(CODESPACES_FILE, codespaces);
    activeSessions.set(id, codespace);

    res.json({ status: 'success', message: 'Codespace started', codespace });
});

app.post('/codespaces/stop/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const codespaces = readJson(CODESPACES_FILE);
    const codespace = codespaces.find(cs => cs.id === id);
    
    if (!codespace) {
        return res.status(404).json({ error: 'Codespace not found' });
    }

    if (codespace.createdBy !== req.user.username) {
        return res.status(403).json({ error: 'Access denied' });
    }

    codespace.status = 'stopped';
    writeJson(CODESPACES_FILE, codespaces);
    activeSessions.delete(id);

    res.json({ status: 'success', message: 'Codespace stopped', codespace });
});

app.delete('/codespaces/delete/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    let codespaces = readJson(CODESPACES_FILE);
    const codespace = codespaces.find(cs => cs.id === id);
    
    if (!codespace) {
        return res.status(404).json({ error: 'Codespace not found' });
    }

    if (codespace.createdBy !== req.user.username) {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const dir = path.join(__dirname, 'codespaces', id);
        if (fs.existsSync(dir)) {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    } catch (err) {
        console.error('Failed to delete codespace directory:', err);
    }

    codespaces = codespaces.filter(cs => cs.id !== id);
    writeJson(CODESPACES_FILE, codespaces);
    activeSessions.delete(id);

    res.json({ status: 'success', message: 'Codespace deleted' });
});

app.post('/codespaces/exec/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { command } = req.body;
    
    const codespaces = readJson(CODESPACES_FILE);
    const codespace = codespaces.find(cs => cs.id === id);
    
    if (!codespace) {
        return res.status(404).json({ error: 'Codespace not found' });
    }

    if (codespace.createdBy !== req.user.username) {
        return res.status(403).json({ error: 'Access denied' });
    }

    if (codespace.status !== 'running') {
        return res.status(400).json({ error: 'Codespace is not running' });
    }

    const cwd = codespace.directory;
    exec(command, { cwd }, (error, stdout, stderr) => {
        res.json({
            status: 'executed',
            command: command,
            stdout: stdout,
            stderr: stderr,
            exitCode: error ? error.code : 0
        });
    });
});

app.get('/codespaces/terminal/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Codespace Terminal - ${id}</title>
            <style>
                body { background: #121212; color: #00ff66; font-family: monospace; padding: 20px; margin: 0; }
                #terminal { background: #000; padding: 20px; border-radius: 5px; height: 70vh; overflow-y: auto; }
                #command-input { background: #1e1e1e; color: #00ff66; border: 1px solid #333; padding: 10px; width: 100%; font-family: monospace; }
                .prompt { color: #00ff66; }
                .output { color: #fff; margin: 5px 0; }
                .error { color: #ff4444; }
            </style>
        </head>
        <body>
            <h2>💻 Codespace Terminal - ${id}</h2>
            <div id="terminal"></div>
            <div style="display: flex; margin-top: 10px;">
                <span class="prompt">$&nbsp;</span>
                <input type="text" id="command-input" placeholder="Enter command..." autofocus>
            </div>
            <br>
            <a href="/codespaces/menu" style="color: #00ff66;">← Back to Codespaces</a>

            <script>
                const terminal = document.getElementById('terminal');
                const commandInput = document.getElementById('command-input');
                const codespaceId = '${id}';
                const token = prompt('Enter Bearer Token:');

                async function executeCommand(cmd) {
                    try {
                        const response = await fetch('/codespaces/exec/' + codespaceId, {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + token,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ command: cmd })
                        });
                        const data = await response.json();
                        
                        if (data.stdout) {
                            const output = document.createElement('div');
                            output.className = 'output';
                            output.textContent = data.stdout;
                            terminal.appendChild(output);
                        }
                        if (data.stderr) {
                            const error = document.createElement('div');
                            error.className = 'error';
                            error.textContent = data.stderr;
                            terminal.appendChild(error);
                        }
                        terminal.scrollTop = terminal.scrollHeight;
                    } catch (err) {
                        const error = document.createElement('div');
                        error.className = 'error';
                        error.textContent = 'Error: ' + err.message;
                        terminal.appendChild(error);
                    }
                }

                commandInput.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter' && commandInput.value.trim()) {
                        const cmd = commandInput.value.trim();
                        const promptLine = document.createElement('div');
                        promptLine.className = 'output';
                        promptLine.textContent = '$ ' + cmd;
                        terminal.appendChild(promptLine);
                        terminal.scrollTop = terminal.scrollHeight;
                        
                        executeCommand(cmd);
                        commandInput.value = '';
                    }
                });

                terminal.innerHTML = '<div class="output">Welcome to Codespace Terminal</div><div class="output">Type commands to execute them</div><div class="output">------------------------------------------------</div>';
            </script>
        </body>
        </html>
    `);
});

// ============ ISSUES ENDPOINTS ============
app.post('/issues/create', authenticateJWT, (req, res) => {
    const { repoName, title, description, labels = [] } = req.body;
    
    if (!repoName || !title) {
        return res.status(400).json({ error: 'repoName and title are required' });
    }

    const repoPath = path.join(REPO_ROOT, repoName);
    if (!fs.existsSync(repoPath)) {
        return res.status(404).json({ error: 'Repository not found' });
    }

    const issues = readJson(ISSUES_FILE);
    const issue = {
        id: 'issue_' + randomHex(8),
        repoName,
        title,
        description: description || '',
        labels: Array.isArray(labels) ? labels : [labels],
        createdBy: req.user.username,
        createdAt: new Date().toISOString(),
        status: 'open',
        comments: []
    };

    issues.push(issue);
    writeJson(ISSUES_FILE, issues);

    res.json({
        status: 'success',
        issue: issue
    });
});

app.get('/issues/list', authenticateJWT, (req, res) => {
    const { repoName } = req.query;
    const issues = readJson(ISSUES_FILE);
    
    let filtered = issues;
    if (repoName) {
        filtered = issues.filter(issue => issue.repoName === repoName);
    }
    
    res.json({ issues: filtered });
});

app.get('/issues/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const issues = readJson(ISSUES_FILE);
    const issue = issues.find(i => i.id === id);
    
    if (!issue) {
        return res.status(404).json({ error: 'Issue not found' });
    }
    
    res.json({ issue });
});

app.put('/issues/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { status, labels, title, description } = req.body;
    
    const issues = readJson(ISSUES_FILE);
    const index = issues.findIndex(i => i.id === id);
    
    if (index === -1) {
        return res.status(404).json({ error: 'Issue not found' });
    }

    if (issues[index].createdBy !== req.user.username) {
        return res.status(403).json({ error: 'Access denied' });
    }

    if (status) issues[index].status = status;
    if (labels) issues[index].labels = labels;
    if (title) issues[index].title = title;
    if (description) issues[index].description = description;
    issues[index].updatedAt = new Date().toISOString();

    writeJson(ISSUES_FILE, issues);
    res.json({ status: 'success', issue: issues[index] });
});

app.post('/issues/:id/comments', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { comment } = req.body;
    
    if (!comment) {
        return res.status(400).json({ error: 'Comment is required' });
    }

    const issues = readJson(ISSUES_FILE);
    const index = issues.findIndex(i => i.id === id);
    
    if (index === -1) {
        return res.status(404).json({ error: 'Issue not found' });
    }

    issues[index].comments.push({
        id: 'cmt_' + randomHex(8),
        comment: comment,
        createdBy: req.user.username,
        createdAt: new Date().toISOString()
    });

    writeJson(ISSUES_FILE, issues);
    res.json({ status: 'success', comment: issues[index].comments[issues[index].comments.length - 1] });
});

// ============ REPOSITORY ENDPOINTS ============
app.post('/create-repo', authenticateJWT, async (req, res) => {
    const { repoName } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    const host = req.get('host');
    if (!fs.existsSync(repoPath)) {
        fs.mkdirSync(repoPath, { recursive: true });
        const git = simpleGit(repoPath);
        await git.init();
        await git.addConfig('http.receivepack', 'true');
        await git.addConfig('receive.denyCurrentBranch', 'updateInstead');
        const cloneUrl = `https://${host}/repos/${repoName}.git`;
        res.send(`<pre>✅ Success: Initialized empty Git repository at ${repoPath}</pre><p>HTTP Clone URL:</p><div class="code-box">git clone ${cloneUrl}</div><br/><a href="/dashboard">Back</a>`);
    } else {
        res.send(`<pre>⚠️ Repository already exists.</pre><a href="/dashboard">Back</a>`);
    }
});

app.get('/get-clone-url', authenticateJWT, (req, res) => {
    const { repoName } = req.query;
    const host = req.get('host');
    const repoUrl = `https://${host}/repos/${repoName}.git`;
    res.send(`<h2>🔗 Repository Endpoint Info</h2><div class="code-box">git clone ${repoUrl}</div><br/><a href="/dashboard">Back</a>`);
});

app.get('/api/list-repos', authenticateJWT, (req, res) => {
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
});

app.get('/api/view-repos', authenticateJWT, (req, res) => {
    res.redirect('/api/list-repos');
});

// ============ OTHER GIT ENDPOINTS ============
app.post('/create-yml', authenticateJWT, async (req, res) => {
    const { repoName, ymlFileName, ymlContents } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    const targetFile = path.join(repoPath, ymlFileName);
    if (!fs.existsSync(repoPath)) return res.status(404).send("Repository not found.");
    fs.writeFileSync(targetFile, ymlContents);
    const git = simpleGit(repoPath);
    await git.add(ymlFileName);
    await git.commit(`Added/updated ${ymlFileName}`);
    res.send(`<pre>✅ File '${ymlFileName}' committed to '${repoName}'.</pre><a href="/dashboard">Back</a>`);
});

app.get('/raw', authenticateJWT, (req, res) => {
    const { repoName, filePath } = req.query;
    const fullPath = path.join(REPO_ROOT, repoName, filePath);
    if (fs.existsSync(fullPath)) {
        res.type('text/plain');
        res.sendFile(fullPath);
    } else {
        res.status(404).send("File not found");
    }
});

app.post('/create-branch', authenticateJWT, async (req, res) => {
    const { repoName, branchName } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    try {
        const git = simpleGit(repoPath);
        await git.checkoutLocalBranch(branchName);
        res.send(`<pre>✅ Branch '${branchName}' checked out in ${repoName}.</pre><a href="/dashboard">Back</a>`);
    } catch (err) {
        res.send(`<pre>Error: ${err.message}</pre><a href="/dashboard">Back</a>`);
    }
});

app.get('/logs', authenticateJWT, async (req, res) => {
    const { repoName } = req.query;
    const repoPath = path.join(REPO_ROOT, repoName);
    try {
        const git = simpleGit(repoPath);
        const logs = await git.log();
        res.type('text/plain').send(JSON.stringify(logs, null, 2));
    } catch (err) {
        res.status(500).send(`Error fetching logs: ${err.message}`);
    }
});

app.post('/run-pipeline', authenticateJWT, (req, res) => {
    const { repoName, pipelineFile } = req.body;
    const repoPath = path.join(REPO_ROOT, repoName);
    const targetFile = path.join(repoPath, pipelineFile);
    const logFile = path.join(repoPath, 'pipeline-execution.log');
    if (!fs.existsSync(targetFile)) {
        return res.status(404).send(`Pipeline file ${pipelineFile} does not exist in repository.`);
    }
    exec(`cd "${repoPath}" && echo "Executing pipeline file: ${pipelineFile}..."`, (error, stdout, stderr) => {
        const output = error ? `Pipeline Execution Error:\n${stderr}` : `Pipeline Execution Output:\n${stdout}`;
        fs.appendFileSync(logFile, `\n--- [${new Date().toISOString()}] Run: ${pipelineFile} ---\n` + output);
        res.send(`<pre>${output}</pre><a href="/dashboard">Back</a>`);
    });
});

app.get('/pipeline-logs', authenticateJWT, (req, res) => {
    const { repoName } = req.query;
    const logFile = path.join(REPO_ROOT, repoName, 'pipeline-execution.log');
    if (fs.existsSync(logFile)) {
        res.type('text/plain').sendFile(logFile);
    } else {
        res.status(404).send(`No execution logs found for repository '${repoName}'. Run a pipeline first.`);
    }
});

// ============ OAUTH ENDPOINTS ============

// OAuth Apps - Create
app.post('/api/oauth/apps', authenticateJWT, (req, res) => {
    const { name, redirect_uri } = req.body;
    if (!name) {
        return res.status(400).json({ error: "application_name_required" });
    }
    const clientId = generateClientId();
    const clientSecret = generateClientSecret();
    const apps = readJson(APPS_FILE);
    apps.push({ 
        id: randomHex(16), 
        name, 
        client_id: clientId, 
        client_secret: clientSecret, 
        redirect_uri: redirect_uri || null,
        created_by: req.user.username,
        created_at: new Date().toISOString() 
    });
    writeJson(APPS_FILE, apps);
    res.status(201).json({ 
        status: "success", 
        name, 
        client_id: clientId, 
        client_secret: clientSecret, 
        redirect_uri: redirect_uri || null 
    });
});

// OAuth Apps - List
app.get('/api/oauth/apps', authenticateJWT, (req, res) => {
    const apps = readJson(APPS_FILE);
    const sanitizedApps = apps.map(app => ({
        name: app.name,
        client_id: app.client_id,
        redirect_uri: app.redirect_uri,
        created_at: app.created_at,
        created_by: app.created_by
    }));
    res.json({ apps: sanitizedApps });
});

// OAuth Authorization Endpoint with PKCE
app.get('/oauth/authorize', (req, res) => {
    const { 
        response_type, 
        client_id, 
        redirect_uri, 
        scope, 
        state,
        code_challenge,
        code_challenge_method,
        id_token_add_organizations,
        codex_cli_simplified_flow,
        originator
    } = req.query;

    if (!response_type || !client_id || !redirect_uri) {
        return res.status(400).send(`
            <h2>Missing Required Parameters</h2>
            <p>response_type, client_id, and redirect_uri are required</p>
        `);
    }

    const apps = readJson(APPS_FILE);
    const app = apps.find(a => a.client_id === client_id);
    if (!app) {
        return res.status(400).send(`<h2>Invalid Client ID</h2><p>The provided client_id does not exist</p>`);
    }

    if (app.redirect_uri && app.redirect_uri !== redirect_uri) {
        return res.status(400).send(`<h2>Invalid Redirect URI</h2><p>The provided redirect_uri does not match the registered one</p>`);
    }

    const authId = randomHex(16);
    const authRequest = {
        id: authId,
        client_id,
        redirect_uri,
        scope: scope || 'openid profile email',
        state: state || null,
        code_challenge: code_challenge || null,
        code_challenge_method: code_challenge_method || 'S256',
        id_token_add_organizations: id_token_add_organizations === 'true',
        codex_cli_simplified_flow: codex_cli_simplified_flow === 'true',
        originator: originator || null,
        created_at: new Date().toISOString()
    };

    const authRequests = readJson(AUTH_CODES_FILE);
    authRequests.push(authRequest);
    writeJson(AUTH_CODES_FILE, authRequests);

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorize Application</title>
            <style>
                body { font-family: monospace; background: #121212; color: #00ff66; padding: 20px; max-width: 600px; margin: 0 auto; }
                h1 { border-bottom: 1px solid #333; padding-bottom: 10px; }
                .app-info { background: #1e1e1e; padding: 15px; border-radius: 5px; margin: 20px 0; }
                form { background: #1e1e1e; padding: 20px; border-radius: 5px; }
                input, button { background: #2b2b2b; color: #fff; border: 1px solid #444; padding: 10px; margin: 5px 0; width: 100%; font-family: monospace; }
                button { background: #0088cc; cursor: pointer; font-weight: bold; }
                button:hover { background: #00aaff; }
                .hint { color: #888; font-size: 12px; }
            </style>
        </head>
        <body>
            <h1>🔐 Authorize Application</h1>
            <div class="app-info">
                <strong>Application:</strong> ${app.name || 'Unknown'}<br>
                <strong>Client ID:</strong> ${client_id}<br>
                <strong>Scope:</strong> ${scope || 'openid profile email'}<br>
                <strong>Redirect URI:</strong> ${redirect_uri}
                ${state ? `<br><strong>State:</strong> ${state}` : ''}
                ${code_challenge ? `<br><strong>PKCE:</strong> Enabled (${code_challenge_method || 'S256'})` : ''}
            </div>
            
            <form action="/oauth/authorize" method="POST">
                <input type="hidden" name="auth_id" value="${authId}">
                <input type="hidden" name="client_id" value="${client_id}">
                <input type="hidden" name="redirect_uri" value="${redirect_uri}">
                <input type="hidden" name="state" value="${state || ''}">
                <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
                <input type="hidden" name="code_challenge_method" value="${code_challenge_method || 'S256'}">
                
                <h3>Login to continue</h3>
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                
                <div style="margin-top: 15px; display: flex; gap: 10px;">
                    <button type="submit" style="width: 100%; background: #00aa44;">Authorize</button>
                </div>
                <p class="hint">Don't have an account? <a href="/api/auth/register" style="color: #00ff66;">Register here</a></p>
            </form>
        </body>
        </html>
    `);
});

// Handle authorization POST
app.post('/oauth/authorize', (req, res) => {
    const { 
        auth_id, 
        client_id, 
        redirect_uri, 
        state, 
        code_challenge, 
        code_challenge_method,
        username, 
        password 
    } = req.body;

    const users = readJson(USERS_FILE);
    const user = users.find(u => u.username === username);
    if (!user || user.passwordHash !== hashPassword(password || '')) {
        return res.status(401).send(`
            <h2>Invalid Credentials</h2>
            <a href="/oauth/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code${state ? `&state=${state}` : ''}${code_challenge ? `&code_challenge=${code_challenge}&code_challenge_method=${code_challenge_method}` : ''}">Try Again</a>
        `);
    }

    const authCode = randomHex(32);
    const codeData = {
        code: authCode,
        client_id,
        redirect_uri,
        user_id: user.id,
        username: user.username,
        state: state || null,
        code_challenge: code_challenge || null,
        code_challenge_method: code_challenge_method || 'S256',
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 600000).toISOString(),
        used: false
    };

    const authCodes = readJson(AUTH_CODES_FILE);
    authCodes.push(codeData);
    writeJson(AUTH_CODES_FILE, authCodes);

    const requests = readJson(AUTH_CODES_FILE);
    const updatedRequests = requests.filter(r => r.id !== auth_id);
    writeJson(AUTH_CODES_FILE, updatedRequests);

    const redirectUrl = `${redirect_uri}?code=${authCode}${state ? `&state=${state}` : ''}`;
    res.redirect(redirectUrl);
});

// Token endpoint with PKCE validation
app.post('/oauth2/token', (req, res) => {
    const { 
        grant_type, 
        code, 
        client_id, 
        client_secret, 
        redirect_uri,
        code_verifier
    } = req.body;

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    const apps = readJson(APPS_FILE);
    const app = apps.find(a => a.client_id === client_id);
    if (!app) {
        return res.status(400).json({ error: 'invalid_client' });
    }

    if (client_secret && app.client_secret !== client_secret) {
        return res.status(400).json({ error: 'invalid_client' });
    }

    const authCodes = readJson(AUTH_CODES_FILE);
    const authCode = authCodes.find(a => a.code === code && !a.used);
    if (!authCode) {
        return res.status(400).json({ error: 'invalid_grant', message: 'Invalid or expired authorization code' });
    }

    if (new Date(authCode.expires_at) < new Date()) {
        authCode.used = true;
        writeJson(AUTH_CODES_FILE, authCodes);
        return res.status(400).json({ error: 'invalid_grant', message: 'Authorization code expired' });
    }

    if (authCode.redirect_uri !== redirect_uri) {
        return res.status(400).json({ error: 'invalid_grant', message: 'Redirect URI mismatch' });
    }

    if (authCode.code_challenge) {
        if (!code_verifier) {
            return res.status(400).json({ error: 'invalid_grant', message: 'Code verifier required for PKCE' });
        }

        const computedChallenge = generateCodeChallenge(code_verifier, authCode.code_challenge_method || 'S256');
        if (computedChallenge !== authCode.code_challenge) {
            return res.status(400).json({ error: 'invalid_grant', message: 'Code verifier validation failed' });
        }
    }

    authCode.used = true;
    writeJson(AUTH_CODES_FILE, authCodes);

    const accessToken = jwt.sign(
        { 
            sub: authCode.user_id, 
            username: authCode.username,
            client_id: client_id,
            jti: randomHex(32),
            scope: 'openid profile email'
        }, 
        OAUTH_SECRET, 
        { expiresIn: '1h' }
    );

    const refreshToken = jwt.sign(
        { 
            sub: authCode.user_id,
            username: authCode.username,
            client_id: client_id,
            jti: randomHex(32)
        },
        OAUTH_SECRET,
        { expiresIn: '7d' }
    );

    res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: refreshToken,
        scope: 'openid profile email'
    });
});

// Generate PKCE
app.get('/api/pkce/generate', authenticateJWT, (req, res) => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    res.json({
        code_verifier: codeVerifier,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
    });
});

// Device OAuth endpoints
app.get('/oauth/device', (req, res) => {
    res.send(`
        <h1>Device Code Login</h1>
        <form action="/login/device" method="POST">
            <input type="text" name="device_code" placeholder="Device Code" required>
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    `);
});

app.post('/oauth/device/code', (req, res) => {
    const deviceCode = randomHex(32);
    const userCode = generateDeviceCode();
    const expiresIn = 600;
    deviceCodes.set(deviceCode, {
        deviceCode, userCode, clientId: req.body.client_id || null,
        username: null, status: 'pending', expiresAt: Date.now() + expiresIn * 1000
    });
    res.json({
        device_code: deviceCode, user_code: userCode,
        verification_uri: `${baseUrl(req)}/oauth/device`,
        expires_in: expiresIn
    });
});

app.post('/login/device', (req, res) => {
    const { device_code, username, password } = req.body;
    let device = null;
    for (const item of deviceCodes.values()) {
        if (item.deviceCode === device_code || item.userCode === device_code.toUpperCase()) {
            device = item;
            break;
        }
    }
    if (!device || Date.now() > device.expiresAt) return res.status(400).send('Invalid or expired device code.');
    const users = readJson(USERS_FILE);
    const user = users.find(u => u.username === username);
    if (!user || user.passwordHash !== hashPassword(password)) return res.status(401).send('Invalid credentials.');
    device.status = 'approved';
    device.username = username;
    res.send('✅ Device Connected Successfully!');
});

app.post('/oauth2/token/device', (req, res) => {
    const { device_code } = req.body;
    const device = deviceCodes.get(device_code);
    if (!device || device.status !== 'approved') return res.status(400).json({ error: 'invalid_device_code' });
    const accessToken = jwt.sign({ sub: device.username, username: device.username, jti: randomHex(32) }, OAUTH_SECRET, { expiresIn: '1h' });
    deviceCodes.delete(device_code);
    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
});

// Authentication endpoints
app.post('/api/auth/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username_and_password_required' });
    const users = readJson(USERS_FILE);
    if (users.some(u => u.username === username)) return res.status(409).json({ error: 'username_already_exists' });
    users.push({ id: randomHex(16), username, passwordHash: hashPassword(password), createdAt: new Date().toISOString() });
    writeJson(USERS_FILE, users);
    res.status(201).json({ status: 'success', message: 'Account created', username });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const users = readJson(USERS_FILE);
    const user = users.find(u => u.username === username);
    if (!user || user.passwordHash !== hashPassword(password || '')) {
        return res.status(401).json({ error: 'invalid_credentials' });
    }
    const accessToken = jwt.sign({ sub: user.id, username: user.username, jti: randomHex(32) }, OAUTH_SECRET, { expiresIn: '1h' });
    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
});

app.get('/api/auth/me', authenticateJWT, (req, res) => {
    res.json({ authenticated: true, username: req.user.username });
});

app.get('/api/whoami', authenticateJWT, (req, res) => {
    res.json({ username: req.user.username, sub: req.user.sub });
});

app.get('/api/oauth/status', authenticateJWT, (req, res) => {
    res.json({ status: 'active', user: req.user.username, token_id: req.user.jti });
});

app.post('/api/auth/logout', authenticateJWT, (req, res) => {
    if (req.user.jti) revokeToken(req.user.jti, req.user.exp);
    res.json({ status: 'success', message: 'Logged out successfully' });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'unified-git-oauth-server' });
});

// Git Smart-HTTP Endpoint Handler
app.all(/^\/repos\/([^\/]+)\.git(.*)$/, authenticateJWT, (req, res) => {
    const repoName = req.params[0];
    const gitPath = req.params[1];
    const repoPath = path.join(REPO_ROOT, repoName);
    if (!fs.existsSync(repoPath)) {
        return res.status(404).send('Git Repository Not Found');
    }
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
        } else {
            res.write(data);
        }
    });
    backend.on('close', () => res.end());
    backend.on('error', (err) => {
        if (!res.headersSent) res.status(500).send(`Git Backend Error: ${err.message}`);
    });
});

// Static Site Deployment Server
app.use('/sites/:repoName', optionalAuth, (req, res, next) => {
    const repoName = req.params.repoName;
    const repoPath = path.join(REPO_ROOT, repoName);
    if (fs.existsSync(repoPath)) {
        express.static(repoPath)(req, res, next);
    } else {
        res.status(404).send('Site Not Found');
    }
});

// Fallback 404
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Not Found',
        message: 'Resource or Site Not Found',
        path: req.path,
        method: req.method
    });
});

// Start Unified Server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Unified Git & OAuth Server running on port ${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`💻 Codespace Menu: http://localhost:${PORT}/codespaces/menu`);
    console.log(`📝 Issues Menu: http://localhost:${PORT}/issues/menu`);
    console.log(`📦 Releases Menu: http://localhost:${PORT}/releases/menu`);
    console.log(`🔐 OAuth Apps: http://localhost:${PORT}/api/oauth/apps`);
    console.log(`🔑 Login: http://localhost:${PORT}/api/auth/login`);
});
