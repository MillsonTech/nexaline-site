const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../db');
const { JWT_SECRET, requireAuth } = require('../middleware/auth');
const { sendOtpEmail } = require('../services/email');

const router = express.Router();

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OTP_EXPIRY_MINUTES = 10;
const OTP_ENABLED = process.env.REQUIRE_OTP !== 'false';

function isStrongPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= 8 &&
    /\d/.test(password) &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password)
  );
}

function generateOtpCode() {
  return crypto.randomInt(0, 1000000).toString().padStart(6, '0');
}

function createAndSendOtp(userId, email, purpose) {
  const code = generateOtpCode();
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000).toISOString();
  db.prepare('INSERT INTO otp_codes (user_id, code, purpose, expires_at) VALUES (?, ?, ?, ?)').run(userId, code, purpose, expiresAt);
  return sendOtpEmail({ to: email, code, purpose });
}

function verifyOtp(userId, code, purpose) {
  const otp = db.prepare('SELECT * FROM otp_codes WHERE user_id = ? AND purpose = ? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1').get(userId, purpose);
  if (!otp) return { valid: false, reason: 'No active code found. Request a new one.' };
  if (otp.code !== code) return { valid: false, reason: 'Incorrect code.' };
  if (new Date(otp.expires_at) < new Date()) return { valid: false, reason: 'This code has expired. Request a new one.' };
  db.prepare("UPDATE otp_codes SET used_at = datetime('now') WHERE id = ?").run(otp.id);
  return { valid: true };
}

// ── GOOGLE OAUTH ──
router.get('/google', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: 'https://nexaline-backend-production.up.railway.app/api/auth/google/callback',
    response_type: 'code',
    scope: 'email profile',
    access_type: 'offline',
    prompt: 'select_account'
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

router.get('/google/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('https://nexalineapp.netlify.app/nexaline-login-register.html?error=no_code');
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: 'https://nexaline-backend-production.up.railway.app/api/auth/google/callback',
        grant_type: 'authorization_code'
      }).toString()
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('No access token');
    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: 'Bearer ' + tokenData.access_token }
    });
    const googleUser = await userRes.json();
    const { email, name } = googleUser;
    if (!email) throw new Error('No email from Google');
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      const hash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10);
      db.prepare('INSERT INTO users (name, email, phone, password_hash, email_verified) VALUES (?,?,?,?,1)')
        .run(name || email.split('@')[0], email, '0000000000', hash);
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    }
    if (user.status === 'suspended') return res.redirect('https://nexalineapp.netlify.app/nexaline-login-register.html?error=suspended');
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.redirect('https://nexalineapp.netlify.app/nexaline-dashboard.html?google_token=' + token + '&user=' + encodeURIComponent(JSON.stringify({ id: user.id, name: user.name, email: user.email, role: user.role })));
  } catch(e) {
    console.error('Google auth error:', e);
    res.redirect('https://nexalineapp.netlify.app/nexaline-login-register.html?error=google_failed');
  }
});

// POST /api/auth/register
router.post('/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Enter your full name.' });
  if (!email || !EMAIL_REGEX.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (!phone || phone.replace(/\D/g, '').length < 7) return res.status(400).json({ error: 'Enter a valid phone number.' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters and include a number, an uppercase and a lowercase letter.' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'An account with this email already exists.' });
  const passwordHash = await bcrypt.hash(password, 10);
  const result = db.prepare('INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)').run(name.trim(), email.toLowerCase(), phone.trim(), passwordHash);
  const userId = result.lastInsertRowid;
  if (!OTP_ENABLED) {
    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(userId);
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
    return res.status(201).json({ message: 'Account created.', token, user: { id: userId, name: name.trim(), email: email.toLowerCase(), role: 'user' } });
  }
  try {
    await createAndSendOtp(userId, email.toLowerCase(), 'email_verification');
  } catch (err) {
    console.error('Failed to send verification email:', err.message);
    return res.status(502).json({ error: "Account created, but we couldn't send the verification email. Try requesting a new code." });
  }
  res.status(201).json({ message: 'Account created. Check your email for a verification code.', userId, email: email.toLowerCase() });
});

// POST /api/auth/verify-email
router.post('/verify-email', (req, res) => {
  const { userId, code } = req.body;
  if (!userId || !code) return res.status(400).json({ error: 'Missing verification details.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  const result = verifyOtp(userId, code, 'email_verification');
  if (!result.valid) return res.status(400).json({ error: result.reason });
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(userId);
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ message: 'Email verified.', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// POST /api/auth/resend-code
router.post('/resend-code', async (req, res) => {
  const { userId, purpose } = req.body;
  if (!userId || !['email_verification', 'login'].includes(purpose)) return res.status(400).json({ error: 'Missing or invalid request.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  try {
    await createAndSendOtp(user.id, user.email, purpose);
  } catch (err) {
    console.error('Failed to resend code:', err.message);
    return res.status(502).json({ error: "Couldn't send the code. Try again shortly." });
  }
  res.json({ message: 'A new code has been sent.' });
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Enter your email and password.' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });
  const passwordMatches = await bcrypt.compare(password, user.password_hash);
  if (!passwordMatches) return res.status(401).json({ error: 'Incorrect email or password.' });
  if (user.status === 'suspended') return res.status(403).json({ error: 'This account has been suspended. Contact support.' });
  if (!OTP_ENABLED) {
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ message: 'Logged in.', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  }
  try {
    await createAndSendOtp(user.id, user.email, 'login');
  } catch (err) {
    console.error('Failed to send login code:', err.message);
    return res.status(502).json({ error: "Couldn't send your login code. Try again shortly." });
  }
  res.json({ message: 'Enter the code sent to your email to finish logging in.', userId: user.id, email: user.email });
});

// POST /api/auth/verify-login
router.post('/verify-login', (req, res) => {
  const { userId, code } = req.body;
  if (!userId || !code) return res.status(400).json({ error: 'Missing verification details.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  if (user.status === 'suspended') return res.status(403).json({ error: 'This account has been suspended. Contact support.' });
  const result = verifyOtp(userId, code, 'login');
  if (!result.valid) return res.status(400).json({ error: result.reason });
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ message: 'Logged in.', token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// GET /api/auth/profile
router.get('/profile', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, phone, wallet_balance_ngn, status, role, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const stats = db.prepare('SELECT COUNT(*) as total_orders, SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) as successful_orders, SUM(CASE WHEN status = ? THEN price_ngn ELSE 0 END) as total_spent_ngn FROM orders WHERE user_id = ?').get('success', 'success', req.user.id);
  res.json({ user, stats });
});

// PATCH /api/auth/profile
router.patch('/profile', requireAuth, (req, res) => {
  const { name, phone } = req.body;
  if (name && name.trim().length < 2) return res.status(400).json({ error: 'Name must be at least 2 characters.' });
  if (phone && phone.replace(/\D/g, '').length < 7) return res.status(400).json({ error: 'Enter a valid phone number.' });
  const updates = [];
  const params = [];
  if (name) { updates.push('name = ?'); params.push(name.trim()); }
  if (phone) { updates.push('phone = ?'); params.push(phone.trim()); }
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update.' });
  params.push(req.user.id);
  db.prepare('UPDATE users SET ' + updates.join(', ') + ' WHERE id = ?').run(...params);
  const updated = db.prepare('SELECT id, name, email, phone, role FROM users WHERE id = ?').get(req.user.id);
  res.json({ message: 'Profile updated.', user: updated });
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Enter your current and new password.' });
  if (!isStrongPassword(newPassword)) return res.status(400).json({ error: 'New password must be at least 8 characters with a number, uppercase and lowercase letter.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const matches = await bcrypt.compare(currentPassword, user.password_hash);
  if (!matches) return res.status(401).json({ error: 'Current password is incorrect.' });
  const newHash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, req.user.id);
  res.json({ message: 'Password updated successfully.' });
});

module.exports = router;
