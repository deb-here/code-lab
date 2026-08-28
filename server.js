const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Ensure data directory exists ────────────────────────────────────────────
const fs = require('fs');
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// ── Database Setup ──────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'data', 'codeeditor.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    github_token TEXT,
    github_username TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    language TEXT DEFAULT 'html',
    code TEXT DEFAULT '',
    github_repo TEXT,
    github_url TEXT,
    is_hosted INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS collaborators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'viewer',
    invited_by INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by) REFERENCES users(id),
    UNIQUE(project_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS project_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    content TEXT DEFAULT '',
    language TEXT DEFAULT 'html',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
  );
`);

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Max 10 users enforcement
const MAX_USERS = 10;

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// Project access helper: returns { project, role } or null
function getProjectAccess(projectId, userId) {
  // Check if owner
  const owned = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId);
  if (owned) return { project: owned, role: 'owner' };

  // Check if collaborator
  const collab = db.prepare('SELECT role FROM collaborators WHERE project_id = ? AND user_id = ?').get(projectId, userId);
  if (collab) {
    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId);
    if (project) return { project, role: collab.role };
  }

  return null;
}

// Check if user can edit (owner or editor)
function canEdit(role) {
  return role === 'owner' || role === 'editor';
}

// ── Auth Routes ─────────────────────────────────────────────────────────────

app.post('/api/register', (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    if (userCount >= MAX_USERS) {
      return res.status(403).json({ error: `Maximum ${MAX_USERS} users reached. Registration closed.` });
    }

    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (existing) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)').run(username, email, hashedPassword);

    req.session.userId = result.lastInsertRowid;
    req.session.username = username;

    res.json({ success: true, user: { id: result.lastInsertRowid, username, email } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, username);
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      user: { id: user.id, username: user.username, email: user.email, github_username: user.github_username }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, github_token, github_username FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { ...user, has_github_token: !!user.github_token } });
});

// ── GitHub Settings ─────────────────────────────────────────────────────────

app.post('/api/github/connect', requireAuth, (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'GitHub token required' });

    // Verify token by calling GitHub API
    axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' }
    }).then(response => {
      const ghUsername = response.data.login;
      db.prepare('UPDATE users SET github_token = ?, github_username = ? WHERE id = ?').run(token, ghUsername, req.session.userId);
      res.json({ success: true, github_username: ghUsername });
    }).catch(() => {
      res.status(400).json({ error: 'Invalid GitHub token' });
    });
  } catch (err) {
    console.error('GitHub connect error:', err);
    res.status(500).json({ error: 'Failed to connect GitHub' });
  }
});

app.post('/api/github/disconnect', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET github_token = NULL, github_username = NULL WHERE id = ?').run(req.session.userId);
  res.json({ success: true });
});

// ── Project Routes ──────────────────────────────────────────────────────────

app.get('/api/projects', requireAuth, (req, res) => {
  const owned = db.prepare("SELECT *, 'owner' as role FROM projects WHERE user_id = ? ORDER BY updated_at DESC").all(req.session.userId);

  const shared = db.prepare(`
    SELECT p.*, c.role
    FROM projects p
    JOIN collaborators c ON c.project_id = p.id
    WHERE c.user_id = ?
    ORDER BY p.updated_at DESC
  `).all(req.session.userId);

  res.json({ projects: owned, shared_projects: shared });
});

app.post('/api/projects', requireAuth, (req, res) => {
  try {
    const { name, description, language } = req.body;
    if (!name) return res.status(400).json({ error: 'Project name required' });

    const defaultCode = getDefaultCode(language || 'html');
    const result = db.prepare(
      'INSERT INTO projects (user_id, name, description, language, code) VALUES (?, ?, ?, ?, ?)'
    ).run(req.session.userId, name, description || '', language || 'html', defaultCode);

    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(result.lastInsertRowid);
    res.json({ success: true, project });
  } catch (err) {
    console.error('Create project error:', err);
    res.status(500).json({ error: 'Failed to create project' });
  }
});

app.get('/api/projects/:id', requireAuth, (req, res) => {
  const access = getProjectAccess(req.params.id, req.session.userId);
  if (!access) return res.status(404).json({ error: 'Project not found' });

  const files = db.prepare('SELECT * FROM project_files WHERE project_id = ? ORDER BY filename').all(access.project.id);
  const collaborators = db.prepare(`
    SELECT c.id, c.role, c.created_at, u.username, u.email
    FROM collaborators c JOIN users u ON u.id = c.user_id
    WHERE c.project_id = ?
  `).all(access.project.id);
  const owner = db.prepare('SELECT username FROM users WHERE id = ?').get(access.project.user_id);

  res.json({ project: access.project, files, role: access.role, collaborators, owner: owner?.username });
});

app.put('/api/projects/:id', requireAuth, (req, res) => {
  try {
    const { name, description, language, code } = req.body;
    const access = getProjectAccess(req.params.id, req.session.userId);
    if (!access) return res.status(404).json({ error: 'Project not found' });
    if (!canEdit(access.role)) return res.status(403).json({ error: 'You have view-only access' });

    db.prepare(
      'UPDATE projects SET name = ?, description = ?, language = ?, code = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).run(name || access.project.name, description ?? access.project.description, language || access.project.language, code ?? access.project.code, access.project.id);

    const updated = db.prepare('SELECT * FROM projects WHERE id = ?').get(access.project.id);
    res.json({ success: true, project: updated });
  } catch (err) {
    console.error('Update project error:', err);
    res.status(500).json({ error: 'Failed to update project' });
  }
});

app.delete('/api/projects/:id', requireAuth, (req, res) => {
  const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!project) return res.status(404).json({ error: 'Project not found' });

  db.prepare('DELETE FROM projects WHERE id = ?').run(project.id);
  res.json({ success: true });
});

// ── Project Files Routes ────────────────────────────────────────────────────

app.post('/api/projects/:id/files', requireAuth, (req, res) => {
  try {
    const { filename, content, language } = req.body;
    const access = getProjectAccess(req.params.id, req.session.userId);
    if (!access) return res.status(404).json({ error: 'Project not found' });
    if (!canEdit(access.role)) return res.status(403).json({ error: 'You have view-only access' });

    const existing = db.prepare('SELECT id FROM project_files WHERE project_id = ? AND filename = ?').get(access.project.id, filename);
    if (existing) {
      db.prepare('UPDATE project_files SET content = ?, language = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
        .run(content || '', language || 'html', existing.id);
    } else {
      db.prepare('INSERT INTO project_files (project_id, filename, content, language) VALUES (?, ?, ?, ?)')
        .run(access.project.id, filename, content || '', language || 'html');
    }

    const files = db.prepare('SELECT * FROM project_files WHERE project_id = ?').all(access.project.id);
    res.json({ success: true, files });
  } catch (err) {
    console.error('Save file error:', err);
    res.status(500).json({ error: 'Failed to save file' });
  }
});

app.delete('/api/projects/:id/files/:fileId', requireAuth, (req, res) => {
  const access = getProjectAccess(req.params.id, req.session.userId);
  if (!access) return res.status(404).json({ error: 'Project not found' });
  if (!canEdit(access.role)) return res.status(403).json({ error: 'You have view-only access' });

  db.prepare('DELETE FROM project_files WHERE id = ? AND project_id = ?').run(req.params.fileId, access.project.id);
  res.json({ success: true });
});

// ── GitHub Push / Host ──────────────────────────────────────────────────────

app.post('/api/projects/:id/push-github', requireAuth, async (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    if (!user.github_token) {
      return res.status(400).json({ error: 'Connect your GitHub account first in Settings' });
    }

    const access = getProjectAccess(req.params.id, req.session.userId);
    if (!access) return res.status(404).json({ error: 'Project not found' });
    if (!canEdit(access.role)) return res.status(403).json({ error: 'You have view-only access' });
    const project = access.project;

    const ghHeaders = {
      Authorization: `token ${user.github_token}`,
      Accept: 'application/vnd.github.v3+json'
    };

    const repoName = project.name.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-');
    let repoFullName;
    let repoUrl;

    // Check if repo already exists
    if (project.github_repo) {
      repoFullName = project.github_repo;
      repoUrl = project.github_url;
    } else {
      // Create new repo
      try {
        const createRes = await axios.post('https://api.github.com/user/repos', {
          name: repoName,
          description: project.description || `Created with NeonCode Editor`,
          auto_init: true,
          private: false
        }, { headers: ghHeaders });

        repoFullName = createRes.data.full_name;
        repoUrl = createRes.data.html_url;
      } catch (createErr) {
        if (createErr.response && createErr.response.status === 422) {
          // Repo might already exist
          repoFullName = `${user.github_username}/${repoName}`;
          repoUrl = `https://github.com/${repoFullName}`;
        } else {
          throw createErr;
        }
      }
    }

    // Prepare files to push
    const files = db.prepare('SELECT * FROM project_files WHERE project_id = ?').all(project.id);
    const filesToPush = [];

    // Add main code file
    if (project.code) {
      const ext = getFileExtension(project.language);
      filesToPush.push({ path: `main${ext}`, content: project.code });
    }

    // Add project files
    for (const file of files) {
      filesToPush.push({ path: file.filename, content: file.content });
    }

    // Add index.html if it's a web project and doesn't exist
    const hasIndex = filesToPush.some(f => f.path === 'index.html');
    if (!hasIndex && ['html', 'css', 'javascript'].includes(project.language)) {
      filesToPush.push({ path: 'index.html', content: generateIndexHtml(project, files) });
    }

    // Push files using GitHub Contents API
    for (const file of filesToPush) {
      const contentBase64 = Buffer.from(file.content || '').toString('base64');
      const filePath = file.path;

      // Check if file exists to get SHA
      let sha;
      try {
        const existingFile = await axios.get(
          `https://api.github.com/repos/${repoFullName}/contents/${filePath}`,
          { headers: ghHeaders }
        );
        sha = existingFile.data.sha;
      } catch {
        // File doesn't exist, that's fine
      }

      await axios.put(
        `https://api.github.com/repos/${repoFullName}/contents/${filePath}`,
        {
          message: `Update ${filePath} via NeonCode Editor`,
          content: contentBase64,
          ...(sha ? { sha } : {})
        },
        { headers: ghHeaders }
      );
    }

    // Enable GitHub Pages
    try {
      await axios.post(
        `https://api.github.com/repos/${repoFullName}/pages`,
        { source: { branch: 'main', path: '/' } },
        { headers: ghHeaders }
      );
    } catch {
      // Pages might already be enabled, or not available
    }

    const pagesUrl = `https://${user.github_username}.github.io/${repoName}/`;

    // Update project with GitHub info
    db.prepare(
      'UPDATE projects SET github_repo = ?, github_url = ?, is_hosted = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).run(repoFullName, repoUrl, project.id);

    res.json({
      success: true,
      repo_url: repoUrl,
      pages_url: pagesUrl,
      repo_name: repoFullName
    });
  } catch (err) {
    console.error('GitHub push error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to push to GitHub: ' + (err.response?.data?.message || err.message) });
  }
});

// ── Collaboration Routes ────────────────────────────────────────────────────

// Invite a user to a project
app.post('/api/projects/:id/collaborators', requireAuth, (req, res) => {
  try {
    const { username, role } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    if (!['viewer', 'editor'].includes(role)) return res.status(400).json({ error: 'Role must be viewer or editor' });

    // Only owner can invite
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
    if (!project) return res.status(403).json({ error: 'Only the project owner can invite collaborators' });

    // Find user to invite
    const invitee = db.prepare('SELECT id, username FROM users WHERE username = ?').get(username);
    if (!invitee) return res.status(404).json({ error: `User "${username}" not found` });
    if (invitee.id === req.session.userId) return res.status(400).json({ error: 'You cannot invite yourself' });

    // Check if already a collaborator
    const existing = db.prepare('SELECT id FROM collaborators WHERE project_id = ? AND user_id = ?').get(project.id, invitee.id);
    if (existing) {
      // Update role instead
      db.prepare('UPDATE collaborators SET role = ? WHERE id = ?').run(role, existing.id);
    } else {
      db.prepare('INSERT INTO collaborators (project_id, user_id, role, invited_by) VALUES (?, ?, ?, ?)')
        .run(project.id, invitee.id, role, req.session.userId);
    }

    const collaborators = db.prepare(`
      SELECT c.id, c.role, c.created_at, u.username, u.email
      FROM collaborators c JOIN users u ON u.id = c.user_id
      WHERE c.project_id = ?
    `).all(project.id);

    res.json({ success: true, collaborators });
  } catch (err) {
    console.error('Invite error:', err);
    res.status(500).json({ error: 'Failed to invite user' });
  }
});

// Update collaborator role
app.put('/api/projects/:id/collaborators/:collabId', requireAuth, (req, res) => {
  try {
    const { role } = req.body;
    if (!['viewer', 'editor'].includes(role)) return res.status(400).json({ error: 'Role must be viewer or editor' });

    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
    if (!project) return res.status(403).json({ error: 'Only the project owner can change roles' });

    db.prepare('UPDATE collaborators SET role = ? WHERE id = ? AND project_id = ?').run(role, req.params.collabId, project.id);

    const collaborators = db.prepare(`
      SELECT c.id, c.role, c.created_at, u.username, u.email
      FROM collaborators c JOIN users u ON u.id = c.user_id
      WHERE c.project_id = ?
    `).all(project.id);

    res.json({ success: true, collaborators });
  } catch (err) {
    console.error('Update role error:', err);
    res.status(500).json({ error: 'Failed to update role' });
  }
});

// Remove collaborator
app.delete('/api/projects/:id/collaborators/:collabId', requireAuth, (req, res) => {
  try {
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
    if (!project) return res.status(403).json({ error: 'Only the project owner can remove collaborators' });

    db.prepare('DELETE FROM collaborators WHERE id = ? AND project_id = ?').run(req.params.collabId, project.id);

    const collaborators = db.prepare(`
      SELECT c.id, c.role, c.created_at, u.username, u.email
      FROM collaborators c JOIN users u ON u.id = c.user_id
      WHERE c.project_id = ?
    `).all(project.id);

    res.json({ success: true, collaborators });
  } catch (err) {
    console.error('Remove collaborator error:', err);
    res.status(500).json({ error: 'Failed to remove collaborator' });
  }
});

// Leave a shared project (for collaborators)
app.post('/api/projects/:id/leave', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM collaborators WHERE project_id = ? AND user_id = ?').run(req.params.id, req.session.userId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to leave project' });
  }
});

// Search users (for invite autocomplete)
app.get('/api/users/search', requireAuth, (req, res) => {
  const q = req.query.q;
  if (!q || q.length < 2) return res.json({ users: [] });
  const users = db.prepare('SELECT id, username FROM users WHERE username LIKE ? AND id != ? LIMIT 5')
    .all(`%${q}%`, req.session.userId);
  res.json({ users });
});

// ── Helper Functions ────────────────────────────────────────────────────────

function getDefaultCode(language) {
  const defaults = {
    html: `<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="UTF-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n  <title>My Project</title>\n  <style>\n    body { font-family: system-ui; background: #0a0a1a; color: #00ff88; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }\n    h1 { text-shadow: 0 0 20px rgba(0,255,136,0.5); }\n  </style>\n</head>\n<body>\n  <h1>Hello, NeonCode! ⚡</h1>\n</body>\n</html>`,
    css: `/* NeonCode CSS */\n:root {\n  --neon-green: #00ff88;\n  --neon-blue: #00d4ff;\n  --dark-bg: #0a0a1a;\n}\n\nbody {\n  background: var(--dark-bg);\n  color: var(--neon-green);\n  font-family: 'Courier New', monospace;\n}\n\n.glow {\n  text-shadow: 0 0 10px var(--neon-blue);\n}`,
    javascript: `// NeonCode JavaScript\nconsole.log('⚡ Welcome to NeonCode!');\n\nfunction greet(name) {\n  return \`Hello, \${name}! Welcome to the future.\`;\n}\n\nconsole.log(greet('Developer'));`,
    python: `# NeonCode Python\nprint("⚡ Welcome to NeonCode!")\n\ndef greet(name):\n    return f"Hello, {name}! Welcome to the future."\n\nprint(greet("Developer"))`,
    sql: `-- NeonCode SQL\nCREATE TABLE IF NOT EXISTS users (\n  id INTEGER PRIMARY KEY,\n  username TEXT NOT NULL,\n  email TEXT UNIQUE,\n  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);\n\nINSERT INTO users (username, email) VALUES ('neo', 'neo@neoncode.dev');\n\nSELECT * FROM users;`
  };
  return defaults[language] || defaults.html;
}

function getFileExtension(language) {
  const exts = { html: '.html', css: '.css', javascript: '.js', python: '.py', sql: '.sql' };
  return exts[language] || '.txt';
}

function generateIndexHtml(project, files) {
  let cssContent = '';
  let jsContent = '';
  let htmlBody = '';

  const cssFile = files.find(f => f.filename.endsWith('.css'));
  const jsFile = files.find(f => f.filename.endsWith('.js'));

  if (project.language === 'html') {
    return project.code;
  }

  if (cssFile) cssContent = cssFile.content;
  if (jsFile) jsContent = jsFile.content;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${project.name}</title>
  <style>${cssContent}</style>
</head>
<body>
  ${htmlBody || '<h1>' + project.name + '</h1><p>Created with NeonCode Editor</p>'}
  <script>${jsContent}</script>
</body>
</html>`;
}

// ── SPA Fallback ────────────────────────────────────────────────────────────

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start Server ────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  ⚡ NeonCode Editor running at http://localhost:${PORT}`);
  console.log(`  📝 Languages: HTML, CSS, JavaScript, Python, SQL`);
  console.log(`  👥 Max users: ${MAX_USERS}`);
  console.log(`  💾 Database: SQLite (${path.join(dataDir, 'codeeditor.db')})\n`);
});
