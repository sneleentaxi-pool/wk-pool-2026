const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN || 'tjeerd';
const API_KEY = process.env.FOOTBALL_API_KEY || ''; // football-data.org API key

// Deadline: no predictions after June 10, 2026 23:59 CET (= June 10 21:59 UTC)
const DEADLINE = new Date(process.env.DEADLINE || '2026-06-10T21:59:00Z');

// Email transporter (set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM in env)
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;

// DB setup
const db = new Database('pool.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY,
    home_team TEXT NOT NULL,
    away_team TEXT NOT NULL,
    match_date TEXT,
    stage TEXT,
    group_name TEXT,
    home_score INTEGER,
    away_score INTEGER,
    status TEXT DEFAULT 'TIMED',
    updated_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    match_id INTEGER,
    home_score INTEGER,
    away_score INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, match_id)
  );
  CREATE TABLE IF NOT EXISTS tournament_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    winner TEXT,
    top_scorer TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS group_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    group_name TEXT,
    position INTEGER,
    team TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, group_name, position)
  );
`);

// Migrate: add email column if not present (existing DBs)
try { db.exec('ALTER TABLE users ADD COLUMN email TEXT'); } catch(e) {}

// Seed WK 2026 groups & matches (static data as fallback)
const WK_GROUPS = {
  'A': ['Qatar', 'Ecuador', 'Senegal', 'Netherlands'],
  'B': ['England', 'Iran', 'USA', 'Wales'],
  'C': ['Argentina', 'Saudi Arabia', 'Mexico', 'Poland'],
  'D': ['France', 'Australia', 'Denmark', 'Tunisia'],
  'E': ['Spain', 'Costa Rica', 'Germany', 'Japan'],
  'F': ['Belgium', 'Canada', 'Morocco', 'Croatia'],
  'G': ['Brazil', 'Serbia', 'Switzerland', 'Cameroon'],
  'H': ['Portugal', 'Ghana', 'Uruguay', 'South Korea'],
  'I': ['Netherlands', 'Senegal', 'Ecuador', 'Qatar'],
  'J': ['USA', 'England', 'Iran', 'Wales'],
  'K': ['Mexico', 'Argentina', 'Poland', 'Saudi Arabia'],
  'L': ['Australia', 'France', 'Tunisia', 'Denmark']
};

// WK 2026 has 48 teams, 12 groups of 4. Use actual WK 2026 groups:
const WK2026_GROUPS = {
  'A': ['Mexico', 'USA', 'Canada', 'Ecuador'],
  'B': ['Spain', 'France', 'Morocco', 'Algeria'],
  'C': ['Brazil', 'Argentina', 'Colombia', 'Uruguay'],
  'D': ['Germany', 'Netherlands', 'Belgium', 'Denmark'],
  'E': ['England', 'Portugal', 'Poland', 'Croatia'],
  'F': ['Japan', 'South Korea', 'Australia', 'Iran'],
  'G': ['Senegal', 'Nigeria', 'Egypt', 'Tunisia'],
  'H': ['Saudi Arabia', 'Qatar', 'UAE', 'Iraq'],
  'I': ['Serbia', 'Switzerland', 'Austria', 'Czech Republic'],
  'J': ['Chile', 'Peru', 'Bolivia', 'Venezuela'],
  'K': ['Turkey', 'Greece', 'Romania', 'Slovakia'],
  'L': ['Ivory Coast', 'DR Congo', 'Cameroon', 'Ghana']
};

// Seed static matches if not present
const matchCount = db.prepare('SELECT COUNT(*) as c FROM matches').get();
if (matchCount.c === 0) {
  let matchId = 1;
  const insert = db.prepare(`INSERT OR IGNORE INTO matches (id, home_team, away_team, match_date, stage, group_name) VALUES (?, ?, ?, ?, ?, ?)`);
  const startDate = new Date('2026-06-11');
  for (const [grp, teams] of Object.entries(WK2026_GROUPS)) {
    const pairs = [[0,1],[2,3],[0,2],[1,3],[0,3],[1,2]];
    for (let i = 0; i < pairs.length; i++) {
      const d = new Date(startDate);
      d.setDate(d.getDate() + Math.floor(matchId / 3));
      const [a, b] = pairs[i];
      insert.run(matchId++, teams[a], teams[b], d.toISOString().split('T')[0], 'GROUP', grp);
    }
  }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'sneleentaxi-wk2026-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Niet ingelogd' });
  next();
};
const requireAdmin = (req, res, next) => {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Geen toegang' });
  next();
};

// ---- AUTH ROUTES ----
app.post('/api/register', (req, res) => {
  const { name, password, email } = req.body;
  if (!name || !password || password.length < 4) return res.status(400).json({ error: 'Naam en wachtwoord (min 4 tekens) verplicht' });
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Geldig e-mailadres verplicht' });
  const hash = bcrypt.hashSync(password, 10);
  const isAdmin = name.toLowerCase() === ADMIN_USER.toLowerCase() ? 1 : 0;
  try {
    const result = db.prepare('INSERT INTO users (name, password, email, is_admin) VALUES (?, ?, ?, ?)').run(name, hash, email, isAdmin);
    req.session.userId = result.lastInsertRowid;
    req.session.userName = name;
    req.session.isAdmin = isAdmin === 1;
    res.json({ success: true, name, isAdmin: isAdmin === 1 });
  } catch(e) {
    res.status(400).json({ error: 'Naam al in gebruik' });
  }
});

app.post('/api/login', (req, res) => {
  const { name, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE LOWER(name) = LOWER(?)').get(name);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Naam of wachtwoord onjuist' });
  req.session.userId = user.id;
  req.session.userName = user.name;
  req.session.isAdmin = user.is_admin === 1;
  res.json({ success: true, name: user.name, isAdmin: user.is_admin === 1 });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, name: req.session.userName, isAdmin: req.session.isAdmin });
});

// ---- MATCHES ----
app.get('/api/matches', requireAuth, (req, res) => {
  const matches = db.prepare('SELECT * FROM matches ORDER BY match_date, id').all();
  res.json(matches);
});

// ---- PREDICTIONS ----
app.get('/api/predictions', requireAuth, (req, res) => {
  const preds = db.prepare('SELECT * FROM predictions WHERE user_id = ?').all(req.session.userId);
  const tp = db.prepare('SELECT * FROM tournament_predictions WHERE user_id = ?').get(req.session.userId);
  const gp = db.prepare('SELECT * FROM group_predictions WHERE user_id = ?').all(req.session.userId);
  res.json({ matchPredictions: preds, tournamentPrediction: tp || {}, groupPredictions: gp });
});

app.get('/api/deadline', (req, res) => {
  res.json({ deadline: DEADLINE.toISOString(), locked: new Date() >= DEADLINE });
});

app.post('/api/predictions/match', requireAuth, (req, res) => {
  if (new Date() >= DEADLINE) return res.status(403).json({ error: 'Inzendingen gesloten – deadline verstreken' });
  const { matchId, homeScore, awayScore } = req.body;
  if (homeScore === undefined || awayScore === undefined) return res.status(400).json({ error: 'Scores verplicht' });
  const match = db.prepare('SELECT * FROM matches WHERE id = ?').get(matchId);
  if (!match) return res.status(404).json({ error: 'Wedstrijd niet gevonden' });
  if (match.status === 'FINISHED') return res.status(400).json({ error: 'Wedstrijd al gespeeld' });
  db.prepare(`INSERT INTO predictions (user_id, match_id, home_score, away_score) VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, match_id) DO UPDATE SET home_score=excluded.home_score, away_score=excluded.away_score`
  ).run(req.session.userId, matchId, homeScore, awayScore);
  res.json({ success: true });
});

app.post('/api/predictions/tournament', requireAuth, (req, res) => {
  if (new Date() >= DEADLINE) return res.status(403).json({ error: 'Inzendingen gesloten – deadline verstreken' });
  const { winner, topScorer } = req.body;
  db.prepare(`INSERT INTO tournament_predictions (user_id, winner, top_scorer) VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET winner=excluded.winner, top_scorer=excluded.top_scorer`
  ).run(req.session.userId, winner, topScorer);
  res.json({ success: true });
});

app.post('/api/predictions/group', requireAuth, (req, res) => {
  if (new Date() >= DEADLINE) return res.status(403).json({ error: 'Inzendingen gesloten – deadline verstreken' });
  const { groupName, ranking } = req.body; // ranking = ['TeamA','TeamB','TeamC','TeamD']
  if (!groupName || !ranking || ranking.length !== 4) return res.status(400).json({ error: 'Ongeldige groepsranking' });
  const del = db.prepare('DELETE FROM group_predictions WHERE user_id = ? AND group_name = ?');
  const ins = db.prepare('INSERT INTO group_predictions (user_id, group_name, position, team) VALUES (?, ?, ?, ?)');
  del.run(req.session.userId, groupName);
  ranking.forEach((team, i) => ins.run(req.session.userId, groupName, i + 1, team));
  res.json({ success: true });
});

// ---- LEADERBOARD ----
app.get('/api/leaderboard', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id, name FROM users').all();
  const finishedMatches = db.prepare("SELECT * FROM matches WHERE status = 'FINISHED'").all();
  
  const results = users.map(user => {
    let points = 0;
    let exactCount = 0;
    let correctCount = 0;
    let predCount = 0;

    for (const match of finishedMatches) {
      const pred = db.prepare('SELECT * FROM predictions WHERE user_id = ? AND match_id = ?').get(user.id, match.id);
      if (!pred) continue;
      predCount++;
      const actualResult = Math.sign(match.home_score - match.away_score);
      const predResult = Math.sign(pred.home_score - pred.away_score);
      if (pred.home_score === match.home_score && pred.away_score === match.away_score) {
        points += 3; exactCount++;
      } else if (actualResult === predResult) {
        points += 1; correctCount++;
      }
    }

    // Bonus: winner prediction (10pts if correct, tourney not done yet -> 0)
    const tp = db.prepare('SELECT * FROM tournament_predictions WHERE user_id = ?').get(user.id);
    
    return { name: user.name, points, exactCount, correctCount, predCount, winner: tp?.winner, topScorer: tp?.top_scorer };
  });

  results.sort((a, b) => b.points - a.points);
  res.json(results);
});

// ---- FETCH LIVE DATA ----
async function fetchLiveScores() {
  if (!API_KEY) return;
  try {
    const resp = await fetch('https://api.football-data.org/v4/competitions/WC/matches?season=2026', {
      headers: { 'X-Auth-Token': API_KEY }
    });
    if (!resp.ok) return;
    const data = await resp.json();
    const update = db.prepare(`UPDATE matches SET home_score=?, away_score=?, status=?, updated_at=datetime('now') WHERE id=?`);
    for (const m of (data.matches || [])) {
      const score = m.score?.fullTime;
      if (score) update.run(score.home, score.away, m.status, m.id);
   