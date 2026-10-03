const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

if (process.env.NODE_ENV === 'production') {
    const missingConfig = ['DB_HOST', 'DB_USER', 'DB_NAME'].filter((key) => !process.env[key]);
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) missingConfig.push('JWT_SECRET (at least 32 characters)');
    if (missingConfig.length) throw new Error(`Missing production configuration: ${missingConfig.join(', ')}`);
}

const app = express();
app.use(express.json());
app.use(session({ secret: process.env.JWT_SECRET || 'change_this_secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());


const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const authController = require('./controllers/authControllers');
authController.setDatabase(pool);
const surveyController = require('./controllers/surveyController');
surveyController.setDatabase(pool);

passport.serializeUser((user, done) => done(null, user.id || user.email));
passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await pool.promise().query('SELECT id, username, email FROM users WHERE id = ? OR email = ?', [id, id]);
        const user = rows[0];
        done(null, user || null);
    } catch (error) {
        done(error, null);
    }
});

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: '/api/auth/google/callback'
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
            if (!email) return done(new Error('Google account email not returned by provider.'));
            const [rows] = await pool.promise().query('SELECT id, username, email FROM users WHERE email = ?', [email]);
            if (rows.length) return done(null, rows[0]);
            const [insert] = await pool.promise().query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [profile.displayName || 'Google User', email, await bcrypt.hash(crypto.randomUUID(), 12)]);
            const user = { id: insert.insertId, username: profile.displayName || 'Google User', email };
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }));
}

const authRoutes = require('./routes/authRoutes');
app.use('/api/auth', authRoutes);
app.use('/api/surveys', require('./routes/surveyRoutes'));
app.use(express.static('public'));

const PORT = process.env.PORT || 4000;

const initializeDatabase = async () => {
    const database = pool.promise();
    await database.query(`CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await database.query(`CREATE TABLE IF NOT EXISTS responses (
        id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, survey_id INT NOT NULL,
        answers JSON NOT NULL, submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (user_id), INDEX (survey_id)
    )`);
    await database.query(`CREATE TABLE IF NOT EXISTS user_mfa (
        user_id INT PRIMARY KEY,
        secret VARCHAR(80) NOT NULL,
        enabled BOOLEAN DEFAULT FALSE,
        type ENUM('totp', 'email_otp') DEFAULT 'totp',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (enabled)
    )`);
    await database.query(`CREATE TABLE IF NOT EXISTS login_otps (
        challenge_id VARCHAR(36) PRIMARY KEY, user_id INT NOT NULL,
        code_hash CHAR(64) NOT NULL, expires_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (user_id), INDEX (expires_at)
    )`);
    await database.query(`CREATE TABLE IF NOT EXISTS surveys (
        id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NULL, title VARCHAR(150) NOT NULL,
        description TEXT, questions JSON NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    const [columns] = await database.query(`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'surveys'`);
    const columnNames = new Set(columns.map((column) => column.COLUMN_NAME));
    if (!columnNames.has('user_id')) await database.query('ALTER TABLE surveys ADD COLUMN user_id INT NULL AFTER id');
    if (!columnNames.has('questions')) await database.query('ALTER TABLE surveys ADD COLUMN questions JSON NULL AFTER description');

    const [[surveyCount]] = await database.query('SELECT COUNT(*) AS count FROM surveys WHERE questions IS NOT NULL');
    if (surveyCount.count === 0) {
        const [users] = await database.query('SELECT id FROM users ORDER BY id LIMIT 1');
        if (users.length) {
            await database.query('INSERT INTO surveys (user_id, title, description, questions) VALUES (?, ?, ?, ?), (?, ?, ?, ?)', [
                users[0].id, 'Your week in focus', 'A short check-in about routines, energy, and the things that shape your day.', JSON.stringify([{ id: 'energy', text: 'What gave you energy this week?' }, { id: 'change', text: 'What is one small change you would like to make?' }]),
                users[0].id, 'Community pulse', 'Help us understand what makes a community feel welcoming and connected.', JSON.stringify([{ id: 'belonging', text: 'What helps you feel that you belong?' }, { id: 'improve', text: 'What could make your community better?' }])
            ]);
        }
    }
};

initializeDatabase().then(() => {
    app.listen(PORT, () => console.log(`Survey App is listening on port ${PORT}.`));
}).catch(async (error) => {
    console.error('Database initialization failed:', error.message);
    await pool.promise().end();
    process.exitCode = 1;
});
