import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';

function postJson(url, payload) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const parsed = new URL(url);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, body });
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, body });
        }
      });
    }).on('error', reject);
  });
}

test('ScamLens Backend Contract - Local Server Integration', async (t) => {
  const TEST_PORT = 3189;
  let serverProcess;

  await t.test('spawns local fallback server on test port', async () => {
    serverProcess = spawn(process.execPath, ['backend/server.js'], {
      env: { ...process.env, PORT: String(TEST_PORT), SHARED_TOKEN: 'test-token' },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Wait for server to come online
    await new Promise((resolve) => setTimeout(resolve, 800));

    const health = await getJson(`http://127.0.0.1:${TEST_PORT}/api/health`);
    assert.equal(health.status, 200);
    assert.equal(health.data.status, 'ok');
    assert.equal(health.data.service, 'ScamLens Local Fallback Server');
  });

  await t.test('handles POST /api/check with authorization token', async () => {
    const res = await postJson(`http://127.0.0.1:${TEST_PORT}/api/check`, {
      token: 'test-token',
      url: 'https://google.com',
      verdict: 'Safe',
      score: 0,
      evidence: []
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.verdict, 'Safe');
    assert.equal(res.data.score, 0);
    assert.ok(res.data.plainExplanation.length > 0);
    assert.ok(res.data.advice.length > 0);
    assert.equal(res.data.source, 'template');
  });

  await t.test('rejects request with invalid token', async () => {
    const res = await postJson(`http://127.0.0.1:${TEST_PORT}/api/check`, {
      token: 'wrong-token',
      url: 'https://google.com'
    });

    assert.equal(res.status, 401);
    assert.equal(res.data.error, 'Unauthorized token');
  });

  await t.test('returns cached result on repeated lookup', async () => {
    const res1 = await postJson(`http://127.0.0.1:${TEST_PORT}/api/check`, {
      token: 'test-token',
      url: 'http://login.micros0ft-verify.com',
      verdict: 'Dangerous',
      score: 85,
      evidence: ['Brand look-alike', 'No HTTPS']
    });

    assert.equal(res1.status, 200);
    assert.equal(res1.data.cached, false);

    const res2 = await postJson(`http://127.0.0.1:${TEST_PORT}/api/check`, {
      token: 'test-token',
      url: 'http://login.micros0ft-verify.com',
      verdict: 'Dangerous',
      score: 85,
      evidence: ['Brand look-alike', 'No HTTPS']
    });

    assert.equal(res2.status, 200);
    assert.equal(res2.data.cached, true);
  });

  t.after(() => {
    if (serverProcess) {
      serverProcess.kill();
    }
  });
});
