const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const { generateSecret, generateURI, verify } = require('otplib');
const qr = require('qrcode');

let db;

exports.setDatabase = (poolInstance) => {
    db = poolInstance;
};

const createToken = (user) => jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    process.env.JWT_SECRET || 'change_this_secret',
    { expiresIn: '7d' }
);

exports.createToken = createToken;

const createMfaChallenge = (userId) => jwt.sign(
    { id: userId, purpose: 'authenticator' },
    process.env.JWT_SECRET || 'change_this_secret',
    { expiresIn: '5m' }
);

const publicUser = (user) => ({ id: user.id, username: user.username, email: user.email });
const otpTransport = process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD
    ? nodemailer.createTransport({ service: 'gmail', auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD } })
    : null;

const sendLoginOtp = async (user, code) => {
    if (!otpTransport) {
        if (process.env.NODE_ENV === 'production') throw new Error('Email OTP delivery is not configured.');
        console.warn(`Gmail OTP is not configured. Using local development code: ${code}`);
        return { devCode: code };
    }
    await otpTransport.sendMail({
        from: process.env.GMAIL_USER,
        to: user.email,
        subject: 'Your Survey App sign-in code',
        text: `Your Survey App verification code is ${code}. It expires in 10 minutes.`,
    });
    return { devCode: null };
};

exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });

    try {
        const normalizedEmail = String(email).trim().toLowerCase();
        const [users] = await db.promise().query('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
        const user = users[0];
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const [mfaRows] = await db.promise().query(
            'SELECT enabled FROM user_mfa WHERE user_id = ?',
            [user.id]
        );
        if (mfaRows[0] && mfaRows[0].enabled) {
            const challengeId = createMfaChallenge(user.id);
            return res.json({ requiresOtp: true, challengeId, email: user.email, method: 'authenticator' });
        }

        const code = crypto.randomInt(100000, 1000000).toString();
        const challengeId = crypto.randomUUID();
        const codeHash = crypto.createHash('sha256').update(code).digest('hex');

        await db.promise().query('DELETE FROM login_otps WHERE user_id = ?', [user.id]);
        await db.promise().query(
            'INSERT INTO login_otps (challenge_id, user_id, code_hash, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
            [challengeId, user.id, codeHash]
        );

        const otpInfo = await sendLoginOtp(user, code);
        return res.json({ requiresOtp: true, challengeId, email: user.email, code: otpInfo.devCode, devMode: !!otpInfo.devCode });
    } catch (error) {
        return res.status(500).json({ message: 'Unable to sign in.', error: error.message });
    }
};

exports.verifyLoginOtp = async (req, res) => {
    const { challengeId, code } = req.body;
    if (!challengeId || !/^\d{6}$/.test(String(code || ''))) {
        return res.status(400).json({ message: 'Enter the six-digit verification code.' });
    }

    try {
        let challenge;
        try {
            challenge = jwt.verify(challengeId, process.env.JWT_SECRET || 'change_this_secret');
        } catch (error) {
            challenge = null;
        }

        if (challenge && challenge.purpose === 'authenticator') {
            const [mfaRows] = await db.promise().query(
                'SELECT secret FROM user_mfa WHERE user_id = ? AND enabled = TRUE',
                [challenge.id]
            );
            const verification = mfaRows.length
                ? await verify({ token: String(code), secret: mfaRows[0].secret })
                : { valid: false };
            if (!verification.valid) {
                return res.status(401).json({ message: 'That authenticator code is invalid or expired.' });
            }
            const [users] = await db.promise().query('SELECT id, username, email FROM users WHERE id = ?', [challenge.id]);
            if (!users.length) return res.status(401).json({ message: 'Unable to verify the sign-in code.' });
            return res.json({ token: createToken(users[0]), user: publicUser(users[0]) });
        }

        const [rows] = await db.promise().query(
            'SELECT o.*, u.id, u.username, u.email FROM login_otps o JOIN users u ON u.id = o.user_id WHERE o.challenge_id = ? AND o.expires_at > NOW()',
            [challengeId]
        );

        const otp = rows[0];
        if (!otp) {
            return res.status(401).json({ message: 'That verification code is invalid or expired.' });
        }

        const incomingHash = crypto.createHash('sha256').update(String(code)).digest();
        const storedHash = Buffer.from(otp.code_hash, 'hex');
        const sameLength = storedHash.length === incomingHash.length;
        const hashesMatch = sameLength && crypto.timingSafeEqual(storedHash, incomingHash);

        if (!hashesMatch) {
            return res.status(401).json({ message: 'That verification code is invalid or expired.' });
        }

        await db.promise().query('DELETE FROM login_otps WHERE challenge_id = ?', [challengeId]);
        const user = { id: otp.id, username: otp.username, email: otp.email };
        return res.json({ token: createToken(user), user: publicUser(user) });
    } catch (error) {
        return res.status(500).json({ message: 'Unable to verify the sign-in code.', error: error.message });
    }
};

exports.googleLogin = passport.authenticate('google', { scope: ['profile', 'email'], session: false });

exports.googleCallback = [
    passport.authenticate('google', { failureRedirect: '/login', session: false }),
    async (req, res) => {
        const user = req.user;
        if (!user || !user.id) return res.status(401).json({ message: 'Unable to sign in with Google.' });
        const [mfaRows] = await db.promise().query('SELECT enabled FROM user_mfa WHERE user_id = ?', [user.id]);
        if (mfaRows[0] && mfaRows[0].enabled) {
            const challengeId = createMfaChallenge(user.id);
            return res.redirect(`/?mfa_challenge=${encodeURIComponent(challengeId)}&email=${encodeURIComponent(user.email || '')}`);
        }
        const token = createToken(user);
        return res.redirect(`/?token=${encodeURIComponent(token)}`);
    }
];

exports.getMfaStatus = async (req, res) => {
    try {
        const [rows] = await db.promise().query('SELECT enabled FROM user_mfa WHERE user_id = ?', [req.user.id]);
        return res.json({ enabled: !!(rows[0] && rows[0].enabled) });
    } catch (error) {
        return res.status(500).json({ message: 'Unable to check authenticator status.', error: error.message });
    }
};

exports.setupMfa = async (req, res) => {
    try {
        if (!req.user || !req.user.id) return res.status(401).json({ message: 'Authentication required.' });
        const secret = generateSecret();
        const otpauth = generateURI({ issuer: 'Survey App', label: req.user.email || 'user@surveyapp.local', secret });
        const qrDataUrl = await qr.toDataURL(otpauth);
        await db.promise().query(
            `INSERT INTO user_mfa (user_id, secret, enabled, type, created_at)
             VALUES (?, ?, FALSE, 'totp', NOW())
             ON DUPLICATE KEY UPDATE secret = VALUES(secret), enabled = FALSE, type = 'totp'`,
            [req.user.id, secret]
        );
        return res.json({ secret, qrDataUrl, otpauth });
    } catch (error) {
        return res.status(500).json({ message: 'Unable to prepare authenticator setup.', error: error.message });
    }
};

exports.verifyMfaSetup = async (req, res) => {
    try {
        const { code } = req.body;
        if (!req.user || !req.user.id) return res.status(401).json({ message: 'Authentication required.' });
        if (!/^\d{6}$/.test(String(code || ''))) return res.status(400).json({ message: 'Enter the six-digit authenticator code.' });
        const [rows] = await db.promise().query('SELECT secret, enabled FROM user_mfa WHERE user_id = ?', [req.user.id]);
        if (!rows.length) return res.status(404).json({ message: 'Authenticator setup not found.' });
        const secret = rows[0].secret;
        const verification = await verify({ token: String(code), secret });
        if (!verification.valid) return res.status(401).json({ message: 'Invalid authenticator code.' });
        await db.promise().query('UPDATE user_mfa SET enabled = TRUE WHERE user_id = ?', [req.user.id]);
        return res.json({ message: 'Authenticator enabled successfully.' });
    } catch (error) {
        return res.status(500).json({ message: 'Unable to verify authenticator code.', error: error.message });
    }
};

exports.registerUser = async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
    if (password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    try {
        const normalizedEmail = email.trim().toLowerCase();
        const [existing] = await db.promise().query('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
        if (existing.length) return res.status(409).json({ message: 'An account with this email already exists.' });
        const hashedPassword = await bcrypt.hash(password, 12);
        const [result] = await db.promise().query(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username.trim(), normalizedEmail, hashedPassword]
        );
        const user = { id: result.insertId, username: username.trim(), email: normalizedEmail };
        const [surveyCount] = await db.promise().query('SELECT COUNT(*) AS count FROM surveys WHERE questions IS NOT NULL');
        if (surveyCount[0].count === 0) {
            await db.promise().query('INSERT INTO surveys (user_id, title, description, questions) VALUES (?, ?, ?, ?), (?, ?, ?, ?)', [
                user.id, 'Your week in focus', 'A short check-in about routines, energy, and the things that shape your day.', JSON.stringify([{ id: 'energy', text: 'What gave you energy this week?' }, { id: 'change', text: 'What is one small change you would like to make?' }]),
                user.id, 'Community pulse', 'Help us understand what makes a community feel welcoming and connected.', JSON.stringify([{ id: 'belonging', text: 'What helps you feel that you belong?' }, { id: 'improve', text: 'What could make your community better?' }])
            ]);
        }
        return res.status(201).json({ token: createToken(user), user });
    } catch (error) {
        return res.status(500).json({ message: 'Unable to create account.', error: error.message });
    }
};
