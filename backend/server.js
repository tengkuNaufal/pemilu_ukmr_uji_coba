require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_DATABASE
});

app.post('/api/login', async (req, res) => {
  const { nim, password } = req.body;
  const [rows] = await db.query('SELECT * FROM users WHERE nim = ?', [nim]);
  if (rows.length === 0) return res.status(401).json({ message: 'NIM tidak ditemukan' });

  const user = rows[0];
  if (!await bcrypt.compare(password, user.password_hash)) {
    return res.status(401).json({ message: 'Password salah' });
  }

  const token = jwt.sign({ user_id: user.id, nim: user.nim }, process.env.JWT_SECRET, { expiresIn: '2h' });
  res.json({ token });
});

function auth(req, res, next) {
  const bearer = req.headers.authorization;
  if (!bearer) return res.status(401).json({ message: 'Token hilang' });
  const token = bearer.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Token tidak valid' });
  }
}

app.get('/api/candidates', auth, async (req, res) => {
  const [candidates] = await db.query('SELECT id, nama, foto_url, visi FROM candidates');
  res.json(candidates);
});

app.post('/api/vote', auth, async (req, res) => {
  const user_id = req.user.user_id;
  const { candidate_id } = req.body;
  const [u] = await db.query('SELECT has_voted FROM users WHERE id = ?', [user_id]);
  if (!u.length) return res.status(404).json({ message: 'User tidak ditemukan' });
  if (u[0].has_voted) return res.status(400).json({ message: 'Sudah memilih' });

  await db.query('INSERT INTO votes (user_id, candidate_id) VALUES (?, ?)', [user_id, candidate_id]);
  await db.query('UPDATE users SET has_voted = 1 WHERE id = ?', [user_id]);
  res.json({ message: 'Voting sukses' });
});

app.get('/api/result', auth, async (req, res) => {
  const [rows] = await db.query(`
    SELECT c.nama, COUNT(v.id) AS total_suara
    FROM candidates c
    LEFT JOIN votes v ON v.candidate_id = c.id
    GROUP BY c.id
  `);
  res.json(rows);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
