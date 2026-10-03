const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'Authentication required.' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'change_this_secret');
        return next();
    } catch (error) {
        return res.status(401).json({ message: 'Your session has expired. Please sign in again.' });
    }
};