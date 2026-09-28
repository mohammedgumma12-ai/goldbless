import 'dotenv/config';
import { createHmac, randomBytes, randomInt, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import rateLimit from 'express-rate-limit';
import pg from 'pg';

const { Pool } = pg;
const root = path.dirname(fileURLToPath(import.meta.url));
const hasDatabase = Boolean(process.env.DATABASE_URL);
const pool = hasDatabase ? new Pool({ connectionString: process.env.DATABASE_URL }) : null;
const app = express();
const port = Number(process.env.PORT || 3001);
const sessionCookie = 'gb_session';
const tronAddressPattern = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;
const txHashPattern = /^[a-fA-F0-9]{64}$/;
const scrypt = promisify(scryptCallback);
const requiredEnv = ['DATABASE_URL', 'RESEND_API_KEY', 'SESSION_SECRET', 'OTP_SECRET', 'ADMIN_API_TOKEN'];

function requireConfigured(...keys) {
  const missing = keys.filter((key) => !process.env[key]);
  return missing;
}

function requireDatabase(request, response, next) {
  if (!pool) return response.status(503).json({ error: 'الخادم غير مهيأ بعد: أضف متغيرات البيئة المطلوبة في Vercel.' });
  next();
}

function requireServices(...keys) {
  return (request, response, next) => {
    const missing = requireConfigured(...keys);
    if (missing.length) return response.status(503).json({ error: 'خدمة الخادم غير مهيأة بعد.' });
    next();
  };
}

app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
app.use(express.static(root, { index: 'index.html', setHeaders(response, filePath) {
  if (filePath.endsWith('.html')) response.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
} }));

const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false });
const financialLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function normalizePhone(value) {
  return typeof value === 'string' ? value.replace(/[\s()-]/g, '') : '';
}

function hash(value, secret = '') {
  return createHmac('sha256', secret).update(value).digest('hex');
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

async function createPasswordHash(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `${salt}:${Buffer.from(derived).toString('hex')}`;
}

async function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, expectedHex] = stored.split(':');
  const actual = Buffer.from(await scrypt(password, salt, 64));
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

async function createSession(userId, response) {
  const token = randomBytes(32).toString('base64url');
  await pool.query(
    'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'30 days\')',
    [hash(token, process.env.SESSION_SECRET), userId]
  );
  response.cookie(sessionCookie, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: '/'
  });
}

async function storeAndSendOtp({ email, code, purpose, phone = null, inviteCode = null, passwordHash = null }) {
  if (!pool) throw new Error('Database is not configured');
  await pool.query(
    `INSERT INTO email_otps (email, otp_hash, invite_code, phone, password_hash, purpose, expires_at, attempts)
     VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '10 minutes', 0)
     ON CONFLICT (email) DO UPDATE SET otp_hash = EXCLUDED.otp_hash,
     invite_code = EXCLUDED.invite_code, phone = EXCLUDED.phone,
     password_hash = EXCLUDED.password_hash, purpose = EXCLUDED.purpose,
     expires_at = EXCLUDED.expires_at, attempts = 0, created_at = NOW()`,
    [email, hash(code, process.env.OTP_SECRET), inviteCode, phone, passwordHash, purpose]
  );
  await sendOtp(email, code, purpose);
}

function sessionTokenFromRequest(request) {
  const cookie = request.headers.cookie || '';
  const item = cookie.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${sessionCookie}=`));
  return item ? decodeURIComponent(item.slice(sessionCookie.length + 1)) : '';
}

async function requireUser(request, response, next) {
  try {
    const token = sessionTokenFromRequest(request);
    if (!token) return response.status(401).json({ error: 'يجب تسجيل الدخول أولاً' });
    const tokenHash = hash(token, process.env.SESSION_SECRET);
    const result = await pool.query(
      `SELECT users.id, users.email, users.invite_code
        , users.phone
       FROM sessions JOIN users ON users.id = sessions.user_id
       WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW()`,
      [tokenHash]
    );
    if (!result.rowCount) return response.status(401).json({ error: 'انتهت الجلسة، سجّل الدخول مجددًا' });
    request.user = result.rows[0];
    next();
  } catch (error) {
    next(error);
  }
}

function requireAdmin(request, response, next) {
  const supplied = request.get('x-admin-token') || '';
  const expected = process.env.ADMIN_API_TOKEN;
  if (!safeEqual(supplied, expected)) return response.status(401).json({ error: 'غير مصرح' });
  next();
}

async function sendOtp(email, code, purpose) {
  const subject = purpose === 'register' ? 'توثيق البريد الإلكتروني' : 'رمز استعادة كلمة المرور';
  const purposeText = purpose === 'register' ? 'لتوثيق بريدك الإلكتروني' : 'لاستعادة كلمة المرور';
  const result = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: process.env.FROM_EMAIL || 'onboarding@resend.dev',
      to: [email],
      subject,
      text: `رمزك ${purposeText} هو ${code}. تنتهي صلاحيته خلال 10 دقائق.`
    })
  });
  if (!result.ok) throw new Error(`Email delivery failed with status ${result.status}`);
}

app.get('/api/config', (_request, response) => {
  response.json({
    network: 'TRON TRC20',
    depositAddress: null,
    depositsEnabled: false
  });
});

app.post('/api/auth/register/request-code', requireDatabase, requireServices('RESEND_API_KEY', 'OTP_SECRET'), otpLimiter, async (request, response, next) => {
  try {
    const email = normalizeEmail(request.body?.email);
    const phone = normalizePhone(request.body?.phone);
    const password = typeof request.body?.password === 'string' ? request.body.password : '';
    const inviteCode = typeof request.body?.inviteCode === 'string' ? request.body.inviteCode.trim() : '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\+[1-9]\d{7,14}$/.test(phone)) {
      return response.status(400).json({ error: 'تحقق من البريد الإلكتروني ورقم الهاتف مع مفتاح الدولة' });
    }
    if (!/^\d{8}$/.test(password)) return response.status(400).json({ error: 'كلمة المرور يجب أن تكون 8 أرقام بالضبط' });
    if (!inviteCode) return response.status(400).json({ error: 'كود الإحالة مطلوب' });
    const duplicate = await pool.query('SELECT 1 FROM users WHERE email = $1 OR phone = $2', [email, phone]);
    if (duplicate.rowCount) return response.status(409).json({ error: 'البريد أو رقم الهاتف مسجل مسبقًا' });
    const referral = await pool.query('SELECT id FROM users WHERE invite_code = $1', [inviteCode]);
    const existingUsers = await pool.query('SELECT EXISTS (SELECT 1 FROM users) AS has_users');
    const validBootstrap = !existingUsers.rows[0].has_users && process.env.BOOTSTRAP_INVITE_CODE && inviteCode === process.env.BOOTSTRAP_INVITE_CODE;
    if (!referral.rowCount && !validBootstrap) return response.status(400).json({ error: 'كود الإحالة غير معروف' });
    const passwordHash = await createPasswordHash(password);
    await storeAndSendOtp({
      email,
      code: String(randomInt(100000, 1000000)),
      purpose: 'register',
      phone,
      inviteCode,
      passwordHash
    });
    response.json({ ok: true, message: 'أُرسل رمز توثيق البريد الإلكتروني' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', requireDatabase, requireServices('SESSION_SECRET'), otpLimiter, async (request, response, next) => {
  try {
    const phone = normalizePhone(request.body?.phone);
    const password = typeof request.body?.password === 'string' ? request.body.password : '';
    if (!/^\+[1-9]\d{7,14}$/.test(phone) || !/^\d{8}$/.test(password)) {
      return response.status(400).json({ error: 'أدخل رقم الهاتف الدولي وكلمة المرور ذات 8 أرقام' });
    }
    const result = await pool.query(
      'SELECT id, email, phone, invite_code, password_hash, email_verified FROM users WHERE phone = $1',
      [phone]
    );
    const user = result.rows[0];
    if (!user || !await verifyPassword(password, user.password_hash)) {
      return response.status(401).json({ error: 'رقم الهاتف أو كلمة المرور غير صحيحة' });
    }
    if (!user.email_verified) return response.status(403).json({ error: 'يجب توثيق البريد الإلكتروني أولًا' });
    await createSession(user.id, response);
    response.json({ user: { id: user.id, email: user.email, phone: user.phone, invite_code: user.invite_code } });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/recovery/request-code', requireDatabase, requireServices('RESEND_API_KEY', 'OTP_SECRET'), otpLimiter, async (request, response, next) => {
  try {
    const email = normalizeEmail(request.body?.email);
    const phone = normalizePhone(request.body?.phone);
    const result = await pool.query('SELECT id FROM users WHERE email = $1 AND phone = $2 AND email_verified = TRUE', [email, phone]);
    if (!result.rowCount) return response.status(404).json({ error: 'لم نجد حسابًا مطابقًا لهذا البريد ورقم الهاتف' });
    await storeAndSendOtp({ email, code: String(randomInt(100000, 1000000)), purpose: 'reset_password', phone });
    response.json({ ok: true, message: 'أُرسل رمز الاستعادة إلى البريد الموثق' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/recovery/reset', requireDatabase, requireServices('OTP_SECRET'), otpLimiter, async (request, response, next) => {
  const email = normalizeEmail(request.body?.email);
  const phone = normalizePhone(request.body?.phone);
  const code = typeof request.body?.code === 'string' ? request.body.code.trim() : '';
  const password = typeof request.body?.password === 'string' ? request.body.password : '';
  if (!/^\d{6}$/.test(code) || !/^\d{8}$/.test(password)) {
    return response.status(400).json({ error: 'رمز الاستعادة أو كلمة المرور الجديدة غير صالحة' });
  }
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    const otpResult = await client.query('SELECT * FROM email_otps WHERE email = $1 FOR UPDATE', [email]);
    const otp = otpResult.rows[0];
    if (!otp || otp.purpose !== 'reset_password' || otp.phone !== phone || new Date(otp.expires_at) <= new Date() || otp.attempts >= 5) {
      await client.query('ROLLBACK');
      return response.status(400).json({ error: 'رمز الاستعادة غير صالح أو منتهي الصلاحية' });
    }
    if (!safeEqual(otp.otp_hash, hash(code, process.env.OTP_SECRET))) {
      await client.query('UPDATE email_otps SET attempts = attempts + 1 WHERE email = $1', [email]);
      await client.query('COMMIT');
      return response.status(400).json({ error: 'رمز الاستعادة غير صحيح' });
    }
    const passwordHash = await createPasswordHash(password);
    const updated = await client.query(
      'UPDATE users SET password_hash = $1 WHERE email = $2 AND phone = $3 AND email_verified = TRUE RETURNING id',
      [passwordHash, email, phone]
    );
    if (!updated.rowCount) {
      await client.query('ROLLBACK');
      return response.status(404).json({ error: 'الحساب غير موجود' });
    }
    await client.query('DELETE FROM email_otps WHERE email = $1', [email]);
    await client.query('DELETE FROM sessions WHERE user_id = $1', [updated.rows[0].id]);
    await client.query('COMMIT');
    response.json({ ok: true, message: 'تم تحديث كلمة المرور. سجّل الدخول بكلمة المرور الجديدة.' });
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    next(error);
  } finally {
    client?.release();
  }
});

app.post('/api/auth/register/verify-code', requireDatabase, requireServices('SESSION_SECRET', 'OTP_SECRET'), otpLimiter, async (request, response, next) => {
  const email = normalizeEmail(request.body?.email);
  const code = typeof request.body?.code === 'string' ? request.body.code.trim() : '';
  if (!/^\d{6}$/.test(code)) return response.status(400).json({ error: 'رمز التحقق غير صالح' });
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    const otpResult = await client.query('SELECT * FROM email_otps WHERE email = $1 FOR UPDATE', [email]);
    const otp = otpResult.rows[0];
    if (!otp || otp.purpose !== 'register' || new Date(otp.expires_at) <= new Date() || otp.attempts >= 5) {
      await client.query('ROLLBACK');
      return response.status(400).json({ error: 'رمز التحقق غير صالح أو منتهي الصلاحية' });
    }
    if (!safeEqual(otp.otp_hash, hash(code, process.env.OTP_SECRET))) {
      await client.query('UPDATE email_otps SET attempts = attempts + 1 WHERE email = $1', [email]);
      await client.query('COMMIT');
      return response.status(400).json({ error: 'رمز التحقق غير صحيح' });
    }
    const referral = await client.query('SELECT id FROM users WHERE invite_code = $1', [otp.invite_code]);
    let referrerId = referral.rows[0]?.id || null;
    if (!referrerId) {
      const existingUsers = await client.query('SELECT EXISTS (SELECT 1 FROM users) AS has_users');
      const validBootstrap = !existingUsers.rows[0].has_users && process.env.BOOTSTRAP_INVITE_CODE && otp.invite_code === process.env.BOOTSTRAP_INVITE_CODE;
      if (!validBootstrap) {
        await client.query('ROLLBACK');
        return response.status(400).json({ error: 'كود الإحالة غير معروف' });
      }
    }
    const created = await client.query(
      `INSERT INTO users (email, phone, password_hash, email_verified, invite_code, referred_by)
       VALUES ($1, $2, $3, TRUE, $4, $5) RETURNING id, email, phone, invite_code`,
      [email, otp.phone, otp.password_hash, `GB${randomBytes(6).toString('hex').toUpperCase()}`, referrerId]
    );
    await client.query('DELETE FROM email_otps WHERE email = $1', [email]);
    await client.query('COMMIT');
    await createSession(created.rows[0].id, response);
    response.json({ user: created.rows[0] });
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    if (error.code === '23505') return response.status(409).json({ error: 'البريد أو رقم الهاتف مسجل مسبقًا' });
    next(error);
  } finally {
    client?.release();
  }
});

app.post('/api/auth/logout', requireDatabase, requireServices('SESSION_SECRET'), async (request, response, next) => {
  try {
    const token = sessionTokenFromRequest(request);
    if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [hash(token, process.env.SESSION_SECRET)]);
    response.clearCookie(sessionCookie, { httpOnly: true, sameSite: 'strict', path: '/' });
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get('/api/me', requireDatabase, requireServices('SESSION_SECRET'), requireUser, async (request, response, next) => {
  try {
    const [balance, referrals] = await Promise.all([
      pool.query(
        `SELECT COALESCE((SELECT SUM(amount) FROM ledger_entries WHERE user_id = $1), 0)::text AS balance,
         COALESCE((SELECT SUM(amount) FROM ledger_entries WHERE user_id = $1 AND entry_type = 'deposit'), 0)::text AS confirmed_deposits,
         COALESCE((SELECT SUM(amount) FROM ledger_entries WHERE user_id = $1 AND entry_type = 'withdrawal'), 0)::text AS paid_withdrawals,
         COALESCE((SELECT SUM(amount) FROM withdrawals WHERE user_id = $1 AND status = 'pending'), 0)::text AS pending_withdrawals`,
        [request.user.id]
      ),
      pool.query('SELECT COUNT(*)::int AS count FROM users WHERE referred_by = $1', [request.user.id])
    ]);
    const totals = balance.rows[0];
    const available = Number(totals.balance) - Number(totals.pending_withdrawals);
    response.json({
      user: request.user,
      balance: totals.balance,
      availableBalance: Math.max(0, available).toFixed(6),
      confirmedDeposits: totals.confirmed_deposits,
      paidWithdrawals: Math.abs(Number(totals.paid_withdrawals)).toFixed(6),
      pendingWithdrawals: totals.pending_withdrawals,
      referralCount: referrals.rows[0].count
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/deposits', requireDatabase, requireUser, financialLimiter, async (request, response, next) => {
  response.status(503).json({ error: 'الإيداعات الحقيقية معطلة في وضع المحاكاة. لا ترسل أموالًا.' });
});

app.post('/api/withdrawals', requireDatabase, requireServices('SESSION_SECRET'), requireUser, financialLimiter, async (request, response, next) => {
  const amount = typeof request.body?.amount === 'string' ? request.body.amount.trim() : String(request.body?.amount ?? '');
  const wallet = typeof request.body?.walletAddress === 'string' ? request.body.walletAddress.trim() : '';
  if (!/^\d{1,8}(?:\.\d{1,6})?$/.test(amount) || Number(amount) < 20 || Number(amount) > 10000000 || !tronAddressPattern.test(wallet)) {
    return response.status(400).json({ error: 'الحد الأدنى 20 USDT ويلزم عنوان TRC20 صالح' });
  }

  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [request.user.id]);
    const balance = await client.query(
      `SELECT COALESCE((SELECT SUM(amount) FROM ledger_entries WHERE user_id = $1), 0)::numeric AS balance,
       COALESCE((SELECT SUM(amount) FROM withdrawals WHERE user_id = $1 AND status = 'pending'), 0)::numeric AS reserved`,
      [request.user.id]
    );
    const available = await client.query('SELECT $1::numeric <= ($2::numeric - $3::numeric) AS enough', [amount, balance.rows[0].balance, balance.rows[0].reserved]);
    if (!available.rows[0].enough) {
      await client.query('ROLLBACK');
      return response.status(400).json({ error: 'الرصيد المتاح لا يكفي لهذا السحب' });
    }
    const result = await client.query(
      'INSERT INTO withdrawals (user_id, wallet_address, amount) VALUES ($1, $2, $3) RETURNING id, amount, status, created_at',
      [request.user.id, wallet, amount]
    );
    await client.query('COMMIT');
    response.status(201).json({ withdrawal: result.rows[0], reviewHours: 72 });
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    next(error);
  } finally {
    client?.release();
  }
});

app.get('/api/admin/requests', requireDatabase, requireServices('ADMIN_API_TOKEN'), requireAdmin, async (_request, response, next) => {
  try {
    const [deposits, withdrawals] = await Promise.all([
      pool.query(
        `SELECT deposits.id, deposits.user_id, users.email, deposits.tx_hash, deposits.amount, deposits.created_at
         FROM deposits JOIN users ON users.id = deposits.user_id
         WHERE deposits.status = 'pending' ORDER BY deposits.created_at ASC`
      ),
      pool.query(
        `SELECT withdrawals.id, withdrawals.user_id, users.email, withdrawals.wallet_address,
         withdrawals.amount, withdrawals.created_at
         FROM withdrawals JOIN users ON users.id = withdrawals.user_id
         WHERE withdrawals.status = 'pending' ORDER BY withdrawals.created_at ASC`
      )
    ]);
    response.json({ deposits: deposits.rows, withdrawals: withdrawals.rows });
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/deposits/:id/confirm', requireDatabase, requireServices('ADMIN_API_TOKEN'), requireAdmin, async (request, response, next) => {
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    const result = await client.query('SELECT * FROM deposits WHERE id = $1 FOR UPDATE', [request.params.id]);
    const deposit = result.rows[0];
    if (!deposit || deposit.status !== 'pending') {
      await client.query('ROLLBACK');
      return response.status(404).json({ error: 'الإيداع غير موجود أو تمت معالجته' });
    }
    await client.query("UPDATE deposits SET status = 'confirmed', resolved_at = NOW() WHERE id = $1", [deposit.id]);
    await client.query(
      "INSERT INTO ledger_entries (user_id, entry_type, amount, reference) VALUES ($1, 'deposit', $2, $3)",
      [deposit.user_id, deposit.amount, `deposit:${deposit.id}`]
    );
    await client.query('COMMIT');
    response.json({ ok: true, message: 'تم اعتماد الإيداع وتسجيله في دفتر الحسابات' });
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    next(error);
  } finally {
    client?.release();
  }
});

app.post('/api/admin/deposits/:id/reject', requireDatabase, requireServices('ADMIN_API_TOKEN'), requireAdmin, async (request, response, next) => {
  try {
    const result = await pool.query(
      "UPDATE deposits SET status = 'rejected', resolved_at = NOW() WHERE id = $1 AND status = 'pending' RETURNING id",
      [request.params.id]
    );
    if (!result.rowCount) return response.status(404).json({ error: 'الإيداع غير موجود أو تمت معالجته' });
    response.json({ ok: true, status: 'rejected' });
  } catch (error) {
    next(error);
  }
});

app.post('/api/admin/withdrawals/:id/resolve', requireDatabase, requireServices('ADMIN_API_TOKEN'), requireAdmin, async (request, response, next) => {
  const decision = request.body?.decision;
  const payoutTxHash = typeof request.body?.payoutTxHash === 'string' ? request.body.payoutTxHash.trim() : '';
  if (!['paid', 'rejected'].includes(decision) || (decision === 'paid' && !txHashPattern.test(payoutTxHash))) {
    return response.status(400).json({ error: 'قرار غير صالح أو بصمة تحويل مفقودة' });
  }

  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    const result = await client.query('SELECT * FROM withdrawals WHERE id = $1 FOR UPDATE', [request.params.id]);
    const withdrawal = result.rows[0];
    if (!withdrawal || withdrawal.status !== 'pending') {
      await client.query('ROLLBACK');
      return response.status(404).json({ error: 'طلب السحب غير موجود أو تمت معالجته' });
    }
    const mature = await client.query("SELECT $1::timestamptz <= NOW() - INTERVAL '72 hours' AS ready", [withdrawal.created_at]);
    if (!mature.rows[0].ready) {
      await client.query('ROLLBACK');
      return response.status(409).json({ error: 'لا يمكن حسم الطلب قبل مرور 72 ساعة' });
    }
    await client.query('SELECT pg_advisory_xact_lock($1)', [withdrawal.user_id]);
    await client.query('UPDATE withdrawals SET status = $1, payout_tx_hash = $2, resolved_at = NOW() WHERE id = $3', [decision, decision === 'paid' ? payoutTxHash : null, withdrawal.id]);
    if (decision === 'paid') {
      await client.query(
        "INSERT INTO ledger_entries (user_id, entry_type, amount, reference) VALUES ($1, 'withdrawal', $2, $3)",
        [withdrawal.user_id, -withdrawal.amount, `withdrawal:${withdrawal.id}`]
      );
    }
    await client.query('COMMIT');
    response.json({ ok: true, status: decision });
  } catch (error) {
    if (client) await client.query('ROLLBACK').catch(() => {});
    next(error);
  } finally {
    client?.release();
  }
});

app.use('/api', (_request, response) => response.status(404).json({ error: 'المسار غير موجود' }));
app.use((error, _request, response, _next) => {
  console.error('API error:', error.message);
  response.status(500).json({ error: 'حدث خطأ داخلي؛ لم يتم تنفيذ العملية' });
});

if (pool) {
  try {
    await pool.query(await readFile(path.join(root, 'schema.sql'), 'utf8'));
  } catch (error) {
    console.error('Database initialization failed:', error.message);
  }
}

export default app;

if (process.env.VERCEL !== '1') {
  app.listen(port, () => console.log(`Goldbless server listening on http://localhost:${port}`));
}

process.on('SIGTERM', async () => {
  if (pool) await pool.end();
  process.exit(0);
});