# ⚡ CODE_LAB 

A futuristic, neon-themed online code editor with real-time collaboration, multi-language support, user accounts, project management, and GitHub integration.

![CODE_LAB](https://img.shields.io/badge/CODE__LAB-⚡_Futuristic_Editor-00ff88?style=for-the-badge&labelColor=0a0a1a)

## Features

- **5 Languages** — HTML, CSS, JavaScript, Python, SQL with full syntax highlighting
- **Monaco Editor** — VS Code's editor engine with a custom cyberpunk theme
- **Live Preview** — Real-time preview for HTML/CSS/JS as you type
- **Real-time Collaboration** — See other users' cursors and edits live via SSE
- **Collaboration Roles** — Invite users as Viewer (read-only) or Editor (full access)
- **Edit History** — Track who edited what and when, with full activity timeline
- **User Accounts** — Register/login system with bcrypt password hashing (max 10 users)
- **Project Management** — Create, save, edit, and delete coding projects
- **Auto-Save** — Code auto-saves every 2 seconds
- **GitHub Integration** — Push projects to GitHub and host via GitHub Pages with one click
- **Futuristic UI** — Neon green/blue/purple cyberpunk aesthetic with animated backgrounds

## Quick Start

```bash
npm install
npm start
```

Open **https://code-lab-2q5x.onrender.com/** in your browser.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js + Express |
| Database | SQLite (better-sqlite3) |
| Auth | bcryptjs + express-session |
| Real-time | Server-Sent Events (SSE) |
| Editor | Monaco Editor |
| GitHub | GitHub REST API (via axios) |
| Frontend | Vanilla HTML/CSS/JS |

## Real-time Collaboration

Multiple users can work on the same project simultaneously:
- Live code syncing — see changes as others type
- Cursor indicators — see which line each collaborator is on
- Active users list — see who's currently in the project

## Collaboration Roles

1. Go to any project → click **👥 Team**
2. Search for a registered username
3. Invite as **Editor** (can edit & push) or **Viewer** (read-only)
4. Collaborators see shared projects on their dashboard

## GitHub Integration

1. Go to **Settings** in the app
2. Paste your GitHub Personal Access Token (needs `repo` scope)
3. Open any project → click **🐙 Push to GitHub**

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + S` | Save project |
| `Ctrl + Enter` | Run code |

## License

MIT
