let db;
exports.setDatabase = (pool) => { db = pool; };
const parseQuestions = (value) => typeof value === 'string' ? JSON.parse(value) : value;
const parseAnswers = (value) => typeof value === 'string' ? JSON.parse(value) : value;

exports.listSurveys = async (req, res) => {
    try {
        const [surveys] = await db.promise().query(`
            SELECT s.id, s.title, s.description, s.questions,
              EXISTS (SELECT 1 FROM responses r WHERE r.survey_id = s.id AND r.user_id = ?) AS completed
            FROM surveys s ORDER BY s.created_at DESC`, [req.user.id]);
        res.json(surveys.map((survey) => ({ ...survey, questions: parseQuestions(survey.questions), completed: Boolean(survey.completed) })));
    } catch (error) { res.status(500).json({ message: 'Unable to load surveys.', error: error.message }); }
};

exports.getSurvey = async (req, res) => {
    try {
        const [rows] = await db.promise().query('SELECT id, title, description, questions FROM surveys WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ message: 'Survey not found.' });
        res.json({ ...rows[0], questions: parseQuestions(rows[0].questions) });
    } catch (error) { res.status(500).json({ message: 'Unable to load survey.', error: error.message }); }
};

exports.submitSurvey = async (req, res) => {
    try {
        const [survey] = await db.promise().query('SELECT id, questions FROM surveys WHERE id = ?', [req.params.id]);
        if (!survey.length) return res.status(404).json({ message: 'Survey not found.' });
        if (!req.body.answers || typeof req.body.answers !== 'object' || Array.isArray(req.body.answers)) {
            return res.status(400).json({ message: 'Survey answers are required.' });
        }
        const questions = parseQuestions(survey[0].questions);
        const answers = {};
        for (const [index, question] of questions.entries()) {
            const answer = req.body.answers[question.id ?? index];
            if (typeof answer !== 'string' || !answer.trim()) {
                return res.status(400).json({ message: 'Please answer every question.' });
            }
            answers[question.text] = answer.trim();
        }
        await db.promise().query('INSERT INTO responses (user_id, survey_id, answers) VALUES (?, ?, ?)', [req.user.id, req.params.id, JSON.stringify(answers)]);
        res.status(201).json({ message: 'Survey submitted successfully.' });
    } catch (error) { res.status(500).json({ message: 'Unable to submit survey.', error: error.message }); }
};

exports.profile = async (req, res) => {
    try {
        const [users] = await db.promise().query('SELECT id, username, email, created_at FROM users WHERE id = ?', [req.user.id]);
        const [responses] = await db.promise().query(`SELECT r.id, r.submitted_at, s.title, r.answers FROM responses r JOIN surveys s ON s.id = r.survey_id WHERE r.user_id = ? ORDER BY r.submitted_at DESC`, [req.user.id]);
        res.json({ user: users[0], responses: responses.map((item) => ({ ...item, answers: parseAnswers(item.answers) })) });
    } catch (error) { res.status(500).json({ message: 'Unable to load profile.', error: error.message }); }
};