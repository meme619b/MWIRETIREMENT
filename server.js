const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// SQLite DB setup
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) console.error(err.message);
  else console.log('Connected to SQLite database.');
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({ secret: 'secretkey', resave: false, saveUninitialized: true }));
app.set('view engine', 'ejs');

// Routes
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

app.post('/register', (req, res) => {
  const { username, password, balance, contributions } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users(username, password, balance, contributions) VALUES (?, ?, ?, ?)',
    [username, hash, balance, contributions], (err) => {
      if (err) return res.send('Error registering');
      res.redirect('/login');
    });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user || !bcrypt.compareSync(password, user.password)) {
      return res.send('Invalid credentials');
    }
    req.session.user = user;
    res.redirect('/dashboard');
  });
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('dashboard', { user: req.session.user });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Server start
app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
