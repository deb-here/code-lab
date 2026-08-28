# ⚡ NeonCode — Futuristic Code Editor

A futuristic, neon-themed online code editor with multi-language support, user accounts, project management, and GitHub integration.

![NeonCode](https://img.shields.io/badge/NeonCode-⚡_Futuristic_Editor-00ff88?style=for-the-badge&labelColor=0a0a1a)

## Features

- **5 Languages** — HTML, CSS, JavaScript, Python, SQL with full syntax highlighting
- **Monaco Editor** — VS Code's editor engine with a custom cyberpunk "NeonCode" theme
- **Live Preview** — Real-time preview for HTML/CSS/JS as you type
- **User Accounts** — Register/login system with bcrypt password hashing (max 10 users)
- **Project Management** — Create, save, edit, and delete coding projects
- **Auto-Save** — Code auto-saves every 2 seconds
- **GitHub Integration** — Push projects to GitHub and host via GitHub Pages with one click
- **Futuristic UI** — Neon green/blue/purple cyberpunk aesthetic with animated backgrounds

## Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm start
```

Open **http://localhost:3000** in your browser.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js + Express |
| Database | SQLite (better-sqlite3) |
| Auth | bcryptjs + express-session |
| Editor | Monaco Editor |
| GitHub | GitHub REST API (via axios) |
| Frontend | Vanilla HTML/CSS/JS (no framework) |

## GitHub Integration

1. Go to **Settings** in the app
2. Paste your GitHub Personal Access Token (needs `repo` scope)
3. Open any project → click **🐙 Push to GitHub**
4. Your project gets its own repo + GitHub Pages hosting

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + S` | Save project |
| `Ctrl + Enter` | Run code |

## License

MIT
