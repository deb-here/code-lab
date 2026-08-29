const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/codelab';

// ── Mongoose Schemas ────────────────────────────────────────────────────────

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  github_token:    { type: String, default: null },
  github_username: { type: String, default: null },
}, { timestamps: true });

const projectSchema = new mongoose.Schema({
  user_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name:        { type: String, required: true },
  description: { type: String, default: '' },
  language:    { type: String, default: 'html' },
  code:        { type: String, default: '' },
  github_repo: { type: String, default: null },
  github_url:  { type: String, default: null },
  is_hosted:   { type: Boolean, default: false },
  last_edited_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  last_edited_at: { type: Date, default: null },
}, { timestamps: true });

const editHistorySchema = new mongoose.Schema({
  project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  user_id:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action:     { type: String, default: 'edit' },
  summary:    { type: String, default: '' },
}, { timestamps: true });

const collaboratorSchema = new mongoose.Schema({
  project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  user_id:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  role:       { type: String, default: 'viewer', enum: ['viewer', 'editor'] },
  invited_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });
collaboratorSchema.index({ project_id: 1, user_id: 1 }, { unique: true });

const projectFileSchema = new mongoose.Schema({
  project_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  filename:   { type: String, required: true },
  content:    { type: String, default: '' },
  language:   { type: String, default: 'html' },
}, { timestamps: true });

const User         = mongoose.model('User', userSchema);
const Project      = mongoose.model('Project', projectSchema);
const EditHistory  = mongoose.model('EditHistory', editHistorySchema);
const Collaborator = mongoose.model('Collaborator', collaboratorSchema);
const ProjectFile  = mongoose.model('ProjectFile', projectFileSchema);

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGO_URI,
    ttl: 24 * 60 * 60, // 1 day
  }),
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Max 10 users enforcement
const MAX_USERS = 10;

// ── Real-time SSE Connections ───────────────────────────────────────────────
const projectClients = new Map();

function broadcastToProject(projectId, event, data, excludeUserId = null) {
  const clients = projectClients.get(String(projectId));
  if (!clients) return;
  const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const [id, client] of clients) {
    if (excludeUserId && client.userId === excludeUserId) continue;
    client.res.write(message);
  }
}

function getActiveUsers(projectId) {
  const clients = projectClients.get(String(projectId));
  if (!clients) return [];
  const seen = new Set();
  const users = [];
  for (const [, client] of clients) {
    if (!seen.has(client.userId)) {
      seen.add(client.userId);
      users.push({ userId: client.userId, username: client.username });
    }
  }
  return users;
}

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// Project access helper: returns { project, role } or null
async function getProjectAccess(projectId, userId) {
  // Check if owner
  const owned = await Project.findOne({ _id: projectId, user_id: userId });
  if (owned) return { project: owned, role: 'owner' };

  // Check if collaborator
  const collab = await Collaborator.findOne({ project_id: projectId, user_id: userId });
  if (collab) {
    const project = await Project.findById(projectId);
    if (project) return { project, role: collab.role };
  }

  return null;
}

// Check if user can edit (owner or editor)
function canEdit(role) {
  return role === 'owner' || role === 'editor';
}

// ── Auth Routes ─────────────────────────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const userCount = await User.countDocuments({ email: { $not: /@guest\.codelab$/ } });
    if (userCount >= MAX_USERS) {
      return res.status(403).json({ error: `Maximum ${MAX_USERS} users reached. Registration closed.` });
    }

    const existing = await User.findOne({ $or: [{ username }, { email }] });
    if (existing) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = await User.create({ username, email, password: hashedPassword });

    req.session.userId = user._id.toString();
    req.session.username = username;

    res.json({ success: true, user: { id: user._id, username, email } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.userId = user._id.toString();
    req.session.username = user.username;

    res.json({
      success: true,
      user: { id: user._id, username: user.username, email: user.email, github_username: user.github_username }
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

app.post('/api/guest', async (req, res) => {
  try {
    const { displayName } = req.body;
    const guestId = crypto.randomBytes(4).toString('hex');
    const username = displayName ? displayName.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '') : `guest_${guestId}`;
    const email = `guest_${guestId}@guest.codelab`;
    const password = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 10);

    // Check if chosen name is taken
    if (displayName) {
      const existing = await User.findOne({ username });
      if (existing) {
        return res.status(409).json({ error: `Name "${username}" is taken. Try another.` });
      }
    }

    const user = await User.create({ username, email, password });

    req.session.userId = user._id.toString();
    req.session.username = username;
    req.session.isGuest = true;

    res.json({ success: true, user: { id: user._id, username, email } });
  } catch (err) {
    console.error('Guest login error:', err);
    res.status(500).json({ error: 'Failed to create guest session' });
  }
});

app.get('/api/me', requireAuth, async (req, res) => {
  const user = await User.findById(req.session.userId).select('username email github_token github_username');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user._id, username: user.username, email: user.email, github_username: user.github_username, has_github_token: !!user.github_token } });
});

// ── GitHub Settings ─────────────────────────────────────────────────────────

app.post('/api/github/connect', requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'GitHub token required' });

    // Verify token by calling GitHub API
    axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' }
    }).then(async (response) => {
      const ghUsername = response.data.login;
      await User.findByIdAndUpdate(req.session.userId, { github_token: token, github_username: ghUsername });
      res.json({ success: true, github_username: ghUsername });
    }).catch(() => {
      res.status(400).json({ error: 'Invalid GitHub token' });
    });
  } catch (err) {
    console.error('GitHub connect error:', err);
    res.status(500).json({ error: 'Failed to connect GitHub' });
  }
});

app.post('/api/github/disconnect', requireAuth, async (req, res) => {
  await User.findByIdAndUpdate(req.session.userId, { github_token: null, github_username: null });
  res.json({ success: true });
});

// ── Project Routes ──────────────────────────────────────────────────────────

app.get('/api/projects', requireAuth, async (req, res) => {
  const userId = req.session.userId;

  const owned = await Project.find({ user_id: userId }).sort({ updatedAt: -1 }).lean();
  const ownedWithRole = owned.map(p => ({ ...p, id: p._id, role: 'owner' }));

  const collabs = await Collaborator.find({ user_id: userId }).lean();
  const sharedProjectIds = collabs.map(c => c.project_id);
  const sharedProjects = await Project.find({ _id: { $in: sharedProjectIds } }).sort({ updatedAt: -1 }).lean();

  const collabMap = {};
  collabs.forEach(c => { collabMap[c.project_id.toString()] = c.role; });
  const sharedWithRole = sharedProjects.map(p => ({ ...p, id: p._id, role: collabMap[p._id.toString()] }));

  // Attach last editor username
  const addEditorInfo = async (projects) => {
    const results = [];
    for (const p of projects) {
      let lastEditorName = null;
      if (p.last_edited_by) {
        const u = await User.findById(p.last_edited_by).select('username');
        if (u) lastEditorName = u.username;
      }
      results.push({ ...p, last_editor_name: lastEditorName });
    }
    return results;
  };

  res.json({ projects: await addEditorInfo(ownedWithRole), shared_projects: await addEditorInfo(sharedWithRole) });
});

app.post('/api/projects', requireAuth, async (req, res) => {
  try {
    const { name, description, language } = req.body;
    if (!name) return res.status(400).json({ error: 'Project name required' });

    const defaultCode = getDefaultCode(language || 'html');
    const project = await Project.create({
      user_id: req.session.userId,
      name,
      description: description || '',
      language: language || 'html',
      code: defaultCode,
    });

    res.json({ success: true, project: { ...project.toObject(), id: project._id } });
  } catch (err) {
    console.error('Create project error:', err);
    res.status(500).json({ error: 'Failed to create project' });
  }
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    const access = await getProjectAccess(req.params.id, req.session.userId);
    if (!access) return res.status(404).json({ error: 'Project not found' });

    const files = await ProjectFile.find({ project_id: access.project._id }).sort({ filename: 1 }).lean();
    const collaborators = await Collaborator.find({ project_id: access.project._id }).lean();

    // Enrich collaborators with user info
    const enrichedCollabs = [];
    for (const c of collaborators) {
      const u = await User.findById(c.user_id).select('username email');
      if (u) {
        enrichedCollabs.push({ id: c._id, role: c.role, created_at: c.createdAt, username: u.username, email: u.email });
      }
    }

    const owner = await User.findById(access.project.user_id).select('username');

    // Get last editor info
    let lastEditor = null;
    if (access.project.last_edited_by) {
      const editorUser = await User.findById(access.project.last_edited_by).select('username');
      if (editorUser) {
        lastEditor = { username: editorUser.username, at: access.project.last_edited_at };
      }
    }

    // Get recent edit history (last 20)
    const history = await EditHistory.find({ project_id: access.project._id })
      .sort({ createdAt: -1 }).limit(20).lean();
    const editHistory = [];
    for (const h of history) {
      const u = await User.findById(h.user_id).select('username');
      editHistory.push({ action: h.action, summary: h.summary, created_at: h.createdAt, username: u?.username });
    }

    const projectObj = access.project.toObject ? access.project.toObject() : access.project;
    res.json({
      project: { ...projectObj, id: projectObj._id },
      files: files.map(f => ({ ...f, id: f._id })),
      role: access.role,
      collaborators: enrichedCollabs,
      owner: owner?.username,
      lastEditor,
      editHistory,
    });
  } catch (err) {
    console.error('Get project error:', err);
    res.status(500).json({ error: 'Failed to load project' });
  }
});

app.put('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    const { name, description, language, code } = req.body;
    const access = await getProjectAccess(req.params.id, req.session.userId);
    if (!access) return res.status(404).json({ error: 'Project not found' });
    if (!canEdit(access.role)) return res.status(403).json({ error: 'You have view-only access' });

    await Project.findByIdAndUpdate(access.project._id, {
      name: name || access.project.name,
      description: description ?? access.project.description,
      language: language || access.project.language,
      code: code ?? access.project.code,
      last_edited_by: req.session.userId,
      last_edited_at: new Date(),
    });

    // Log edit history
    await EditHistory.create({
      project_id: access.project._id,
      user_id: req.session.userId,
      action: 'edit',
      summary: `Edited by ${req.session.username}`,
    });

    const updated = await Project.findById(access.project._id).lean();
    res.json({ success: true, project: { ...updated, id: updated._id } });
  } catch (err) {
    console.error('Update project error:', err);
    res.status(500).json({ error: 'Failed to update project' });
  }
});

app.delete('/api/projects/:id', requireAuth, async (req, res) => {
  const project = await Project.findOne({ _id: req.params.id, user_id: req.session.userId });
  if (!project) return res.status(404).json({ error: 'Project not found' });

  // Cascade delete related data
  await Promise.all([
    ProjectFile.deleteMany({ project_id: project._id }),
    EditHistory.deleteMany({ project_id: project._id }),
    Collaborator.deleteMany({ project_id: project._id }),
    Project.findByIdAndDelete(project._id),
  ]);

  res.json({ success: true });
});

// ── Project Files Routes ────────────────────────────────────────────────────

app.post('/api/projects/:id/files', requireAuth, async (req, res) => {
  try {
    const { filename, content, language } = req.body;
    const access = await getProjectAccess(req.params.id, req.session.userId);
    if (!access) return res.status(404).json({ error: 'Project not found' });
    if (!canEdit(access.role)) return res.status(403).json({ error: 'You have view-only access' });

    const existing = await ProjectFile.findOne({ project_id: access.project._id, filename });
    if (existing) {
      await ProjectFile.findByIdAndUpdate(existing._id, { content: content || '', language: language || 'html' });
    } else {
      await ProjectFile.create({ project_id: access.project._id, filename, content: content || '', language: language || 'html' });
    }

    const files = await ProjectFile.find({ project_id: access.project._id }).lean();
    res.json({ success: true, files: files.map(f => ({ ...f, id: f._id })) });
  } catch (err) {
    console.error('Save file error:', err);
    res.status(500).json({ error: 'Failed to save file' });
  }
});

app.delete('/api/projects/:id/files/:fileId', requireAuth, async (req, res) => {
  const access = await getProjectAccess(req.params.id, req.session.userId);
  if (!access) return res.status(404).json({ error: 'Project not found' });
  if (!canEdit(access.role)) return res.status(403).json({ error: 'You have view-only access' });

  await ProjectFile.deleteOne({ _id: req.params.fileId, project_id: access.project._id });
  res.json({ success: true });
});

// ── GitHub Push / Host ──────────────────────────────────────────────────────

app.post('/api/projects/:id/push-github', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user.github_token) {
      return res.status(400).json({ error: 'Connect your GitHub account first in Settings' });
    }

    const access = await getProjectAccess(req.params.id, req.session.userId);
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
          description: project.description || `Created with CODE_LAB Editor`,
          auto_init: true,
          private: false
        }, { headers: ghHeaders });

        repoFullName = createRes.data.full_name;
        repoUrl = createRes.data.html_url;
      } catch (createErr) {
        if (createErr.response && createErr.response.status === 422) {
          repoFullName = `${user.github_username}/${repoName}`;
          repoUrl = `https://github.com/${repoFullName}`;
        } else {
          throw createErr;
        }
      }
    }

    // Prepare files to push
    const files = await ProjectFile.find({ project_id: project._id }).lean();
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

      let sha;
      try {
        const existingFile = await axios.get(
          `https://api.github.com/repos/${repoFullName}/contents/${filePath}`,
          { headers: ghHeaders }
        );
        sha = existingFile.data.sha;
      } catch {
        // File doesn't exist
      }

      await axios.put(
        `https://api.github.com/repos/${repoFullName}/contents/${filePath}`,
        {
          message: `Update ${filePath} via CODE_LAB Editor`,
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
      // Pages might already be enabled
    }

    const pagesUrl = `https://${user.github_username}.github.io/${repoName}/`;

    // Update project with GitHub info
    await Project.findByIdAndUpdate(project._id, {
      github_repo: repoFullName,
      github_url: repoUrl,
      is_hosted: true,
    });

    // Log push to edit history
    await EditHistory.create({
      project_id: project._id,
      user_id: req.session.userId,
      action: 'push',
      summary: `Pushed to GitHub by ${req.session.username}`,
    });

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

// ── Real-time SSE Endpoints ─────────────────────────────────────────────────

app.get('/api/projects/:id/live', requireAuth, async (req, res) => {
  const access = await getProjectAccess(req.params.id, req.session.userId);
  if (!access) return res.status(404).json({ error: 'Project not found' });

  const projectId = String(req.params.id);
  const clientId = crypto.randomBytes(8).toString('hex');

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });

  if (!projectClients.has(projectId)) {
    projectClients.set(projectId, new Map());
  }
  projectClients.get(projectId).set(clientId, {
    res,
    userId: req.session.userId,
    username: req.session.username
  });

  const activeUsers = getActiveUsers(projectId);
  res.write(`event: connected\ndata: ${JSON.stringify({ clientId, activeUsers })}\n\n`);

  broadcastToProject(projectId, 'user-joined', {
    userId: req.session.userId,
    username: req.session.username,
    activeUsers
  }, req.session.userId);

  const heartbeat = setInterval(() => {
    res.write(': heartbeat\n\n');
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    const clients = projectClients.get(projectId);
    if (clients) {
      clients.delete(clientId);
      if (clients.size === 0) {
        projectClients.delete(projectId);
      } else {
        const activeUsers = getActiveUsers(projectId);
        broadcastToProject(projectId, 'user-left', {
          userId: req.session.userId,
          username: req.session.username,
          activeUsers
        });
      }
    }
  });
});

app.post('/api/projects/:id/cursor', requireAuth, (req, res) => {
  const { line, column } = req.body;
  broadcastToProject(req.params.id, 'cursor', {
    userId: req.session.userId,
    username: req.session.username,
    line, column
  }, req.session.userId);
  res.json({ ok: true });
});

app.post('/api/projects/:id/live-edit', requireAuth, (req, res) => {
  const { code, line, column } = req.body;
  broadcastToProject(req.params.id, 'code-update', {
    userId: req.session.userId,
    username: req.session.username,
    code, line, column
  }, req.session.userId);
  res.json({ ok: true });
});

// ── Code Execution Routes ───────────────────────────────────────────────────

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

app.post('/api/execute', requireAuth, (req, res) => {
  const { code, language } = req.body;
  if (!code) return res.status(400).json({ error: 'No code provided' });

  if (language === 'python') {
    executePython(code, res);
  } else if (language === 'sql') {
    executeSql(code, req.session.userId, res);
  } else if (language === 'javascript') {
    executeJavaScript(code, res);
  } else {
    res.json({ output: 'Run is only supported for Python, SQL, and JavaScript.' });
  }
});

function executePython(code, res) {
  const { execFile } = require('child_process');
  const tmpFile = path.join(dataDir, `run_${Date.now()}.py`);

  fs.writeFileSync(tmpFile, code);

  execFile('python3', [tmpFile], {
    timeout: 10000,
    maxBuffer: 1024 * 512,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  }, (error, stdout, stderr) => {
    try { fs.unlinkSync(tmpFile); } catch {}

    if (error && error.killed) {
      return res.json({ output: '', error: '⏱ Execution timed out (10s limit)' });
    }

    res.json({
      output: stdout || '',
      error: stderr || (error ? error.message : '')
    });
  });
}

function executeSql(code, userId, res) {
  // SQL sandbox execution — still uses a temp SQLite file for user sandboxes
  // This is intentional: the sandbox is ephemeral per-session, not persistent data
  try {
    // Simple in-memory SQL simulation for basic queries
    const statements = code.split(';').filter(s => s.trim() && !s.trim().startsWith('--'));
    const results = [];

    for (const stmt of statements) {
      const trimmed = stmt.trim();
      if (!trimmed) continue;
      results.push(`⚠ SQL sandbox is not available in this environment. Push your code to GitHub and use a real database.`);
      break;
    }

    res.json({ output: results.join('\n\n') || 'No statements to execute.' });
  } catch (err) {
    res.json({ output: '', error: err.message });
  }
}

function executeJavaScript(code, res) {
  const { execFile } = require('child_process');
  const tmpFile = path.join(dataDir, `run_${Date.now()}.js`);

  fs.writeFileSync(tmpFile, code);

  execFile('node', [tmpFile], {
    timeout: 10000,
    maxBuffer: 1024 * 512
  }, (error, stdout, stderr) => {
    try { fs.unlinkSync(tmpFile); } catch {}

    if (error && error.killed) {
      return res.json({ output: '', error: '⏱ Execution timed out (10s limit)' });
    }

    res.json({
      output: stdout || '',
      error: stderr || (error ? error.message : '')
    });
  });
}

// ── Collaboration Routes ────────────────────────────────────────────────────

app.post('/api/projects/:id/collaborators', requireAuth, async (req, res) => {
  try {
    const { username, role } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    if (!['viewer', 'editor'].includes(role)) return res.status(400).json({ error: 'Role must be viewer or editor' });

    const project = await Project.findOne({ _id: req.params.id, user_id: req.session.userId });
    if (!project) return res.status(403).json({ error: 'Only the project owner can invite collaborators' });

    const invitee = await User.findOne({ username });
    if (!invitee) return res.status(404).json({ error: `User "${username}" not found` });
    if (invitee._id.toString() === req.session.userId) return res.status(400).json({ error: 'You cannot invite yourself' });

    const existing = await Collaborator.findOne({ project_id: project._id, user_id: invitee._id });
    if (existing) {
      await Collaborator.findByIdAndUpdate(existing._id, { role });
    } else {
      await Collaborator.create({ project_id: project._id, user_id: invitee._id, role, invited_by: req.session.userId });
    }

    const collaborators = await Collaborator.find({ project_id: project._id }).lean();
    const enriched = [];
    for (const c of collaborators) {
      const u = await User.findById(c.user_id).select('username email');
      if (u) enriched.push({ id: c._id, role: c.role, created_at: c.createdAt, username: u.username, email: u.email });
    }

    res.json({ success: true, collaborators: enriched });
  } catch (err) {
    console.error('Invite error:', err);
    res.status(500).json({ error: 'Failed to invite user' });
  }
});

app.put('/api/projects/:id/collaborators/:collabId', requireAuth, async (req, res) => {
  try {
    const { role } = req.body;
    if (!['viewer', 'editor'].includes(role)) return res.status(400).json({ error: 'Role must be viewer or editor' });

    const project = await Project.findOne({ _id: req.params.id, user_id: req.session.userId });
    if (!project) return res.status(403).json({ error: 'Only the project owner can change roles' });

    await Collaborator.findOneAndUpdate({ _id: req.params.collabId, project_id: project._id }, { role });

    const collaborators = await Collaborator.find({ project_id: project._id }).lean();
    const enriched = [];
    for (const c of collaborators) {
      const u = await User.findById(c.user_id).select('username email');
      if (u) enriched.push({ id: c._id, role: c.role, created_at: c.createdAt, username: u.username, email: u.email });
    }

    res.json({ success: true, collaborators: enriched });
  } catch (err) {
    console.error('Update role error:', err);
    res.status(500).json({ error: 'Failed to update role' });
  }
});

app.delete('/api/projects/:id/collaborators/:collabId', requireAuth, async (req, res) => {
  try {
    const project = await Project.findOne({ _id: req.params.id, user_id: req.session.userId });
    if (!project) return res.status(403).json({ error: 'Only the project owner can remove collaborators' });

    await Collaborator.deleteOne({ _id: req.params.collabId, project_id: project._id });

    const collaborators = await Collaborator.find({ project_id: project._id }).lean();
    const enriched = [];
    for (const c of collaborators) {
      const u = await User.findById(c.user_id).select('username email');
      if (u) enriched.push({ id: c._id, role: c.role, created_at: c.createdAt, username: u.username, email: u.email });
    }

    res.json({ success: true, collaborators: enriched });
  } catch (err) {
    console.error('Remove collaborator error:', err);
    res.status(500).json({ error: 'Failed to remove collaborator' });
  }
});

app.post('/api/projects/:id/leave', requireAuth, async (req, res) => {
  try {
    await Collaborator.deleteOne({ project_id: req.params.id, user_id: req.session.userId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to leave project' });
  }
});

app.get('/api/users/search', requireAuth, async (req, res) => {
  const q = req.query.q;
  if (!q || q.length < 2) return res.json({ users: [] });
  const users = await User.find({
    username: { $regex: q, $options: 'i' },
    _id: { $ne: req.session.userId }
  }).select('username').limit(5).lean();
  res.json({ users: users.map(u => ({ id: u._id, username: u.username })) });
});

// ── Helper Functions ────────────────────────────────────────────────────────

function getDefaultCode(language) {
  const defaults = {
    html: `<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="UTF-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n  <title>My Project</title>\n  <style>\n    body { font-family: system-ui; background: #0a0a1a; color: #00ff88; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }\n    h1 { text-shadow: 0 0 20px rgba(0,255,136,0.5); }\n  </style>\n</head>\n<body>\n  <h1>Hello, CODE_LAB! ⚡</h1>\n</body>\n</html>`,
    css: `/* CODE_LAB CSS */\n:root {\n  --neon-green: #00ff88;\n  --neon-blue: #00d4ff;\n  --dark-bg: #0a0a1a;\n}\n\nbody {\n  background: var(--dark-bg);\n  color: var(--neon-green);\n  font-family: 'Courier New', monospace;\n}\n\n.glow {\n  text-shadow: 0 0 10px var(--neon-blue);\n}`,
    javascript: `// CODE_LAB JavaScript\nconsole.log('⚡ Welcome to CODE_LAB!');\n\nfunction greet(name) {\n  return \`Hello, \${name}! Welcome to the future.\`;\n}\n\nconsole.log(greet('Developer'));`,
    python: `# CODE_LAB Python\nprint("⚡ Welcome to CODE_LAB!")\n\ndef greet(name):\n    return f"Hello, {name}! Welcome to the future."\n\nprint(greet("Developer"))`,
    sql: `-- CODE_LAB SQL\nCREATE TABLE IF NOT EXISTS users (\n  id INTEGER PRIMARY KEY,\n  username TEXT NOT NULL,\n  email TEXT UNIQUE,\n  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);\n\nINSERT INTO users (username, email) VALUES ('neo', 'neo@codelab.dev');\n\nSELECT * FROM users;`
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
  ${htmlBody || '<h1>' + project.name + '</h1><p>Created with CODE_LAB Editor</p>'}
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

// ── Connect to MongoDB & Start Server ───────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('  ✅ Connected to MongoDB');
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n  ⚡ CODE_LAB Editor running at http://localhost:${PORT}`);
      console.log(`  📝 Languages: HTML, CSS, JavaScript, Python, SQL`);
      console.log(`  👥 Max users: ${MAX_USERS}`);
      console.log(`  💾 Database: MongoDB Atlas\n`);
    });
  })
  .catch(err => {
    console.error('  ❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });
