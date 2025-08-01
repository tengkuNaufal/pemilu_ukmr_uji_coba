require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

app.post('/api/login', async (req, res) => {
  const { nim, password } = req.body;

  const { data: users, error } = await supabase
    .from('users')
    .select('*')
    .eq('nim', nim)
    .limit(1);

  if (error) return res.status(500).json({ message: 'Supabase error', error });
  if (!users || users.length === 0) return res.status(401).json({ message: 'NIM tidak ditemukan' });

  const user = users[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ message: 'Password salah' });

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
  const { data, error } = await supabase
    .from('candidates')
    .select('id, nama, foto_url, visi');

  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post('/api/vote', auth, async (req, res) => {
  const user_id = req.user.user_id;
  const { candidate_id } = req.body;

  const { data: user, error: userError } = await supabase
    .from('users')
    .select('has_voted')
    .eq('id', user_id)
    .single();

  if (userError) return res.status(500).json({ message: 'Supabase error', error: userError });
  if (!user) return res.status(404).json({ message: 'User tidak ditemukan' });
  if (user.has_voted) return res.status(400).json({ message: 'Sudah memilih' });

  const { error: voteError } = await supabase
    .from('votes')
    .insert({ user_id, candidate_id });

  if (voteError) return res.status(500).json({ message: 'Gagal menyimpan suara', error: voteError });

  const { error: updateError } = await supabase
    .from('users')
    .update({ has_voted: true })
    .eq('id', user_id);

  if (updateError) return res.status(500).json({ message: 'Gagal update status voting', error: updateError });

  res.json({ message: 'Voting sukses' });
});

app.get('/api/result', auth, async (req, res) => {
  const { data, error } = await supabase.rpc('get_vote_result'); // atau pakai raw SQL dengan Supabase client

  if (error) return res.status(500).json({ error });

  res.json(data);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
