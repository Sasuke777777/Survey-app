const assert = require('assert');
const surveyController = require('../controllers/surveyController');

(async () => {
  const savedResponses = [];
  const survey = {
    id: 3,
    title: 'Weekly check-in',
    questions: [{ id: 'energy', text: 'What gave you energy this week?' }]
  };
  const database = {
    promise() {
      return {
        async query(sql, params) {
          if (sql.includes('SELECT id, questions FROM surveys')) return [[survey]];
          if (sql.includes('INSERT INTO responses')) {
            savedResponses.push({
              id: savedResponses.length + 1,
              user_id: params[0],
              survey_id: Number(params[1]),
              answers: params[2],
              submitted_at: '2026-01-01T00:00:00.000Z',
              title: survey.title
            });
            return [{ insertId: savedResponses.length }];
          }
          if (sql.includes('SELECT id, username, email, created_at FROM users')) {
            return [[{ id: 7, username: 'demo', email: 'demo@example.com' }]];
          }
          if (sql.includes('FROM responses r JOIN surveys')) return [savedResponses];
          throw new Error(`Unexpected query: ${sql}`);
        }
      };
    }
  };

  surveyController.setDatabase(database);
  let statusCode;
  let payload;
  const res = {
    status(code) { statusCode = code; return this; },
    json(value) { payload = value; return this; }
  };

  await surveyController.submitSurvey({
    params: { id: '3' },
    user: { id: 7 },
    body: { answers: { energy: 'A walk outside.' } }
  }, res);
  assert.strictEqual(statusCode, 201, 'valid responses should be accepted');
  assert.strictEqual(savedResponses.length, 1, 'submission should persist one response');

  statusCode = undefined;
  payload = undefined;
  await surveyController.profile({ user: { id: 7 } }, res);
  assert.strictEqual(payload.responses.length, 1, 'saved responses should appear in the profile');
  assert.deepStrictEqual(payload.responses[0].answers, { 'What gave you energy this week?': 'A walk outside.' });

  statusCode = undefined;
  await surveyController.submitSurvey({
    params: { id: '3' },
    user: { id: 7 },
    body: { answers: { energy: '   ' } }
  }, res);
  assert.strictEqual(statusCode, 400, 'empty answers should be rejected');

  console.log('survey-flow test passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});