import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeUrl,
  parseUrlSafely,
  getRegistrableDomain,
  levenshteinDistance,
  isIPv4Literal,
  isIPv6Literal,
  hasHomographOrPunycode,
  checkBrandLookalike
} from '../src/scripts/rules.js';

describe('ScamLens Rules Engine - Unit Tests', () => {

  describe('Helper Functions', () => {
    it('parseUrlSafely handles standard, bare, and malformed inputs', () => {
      assert.equal(parseUrlSafely('https://example.com/path')?.host, 'example.com');
      assert.equal(parseUrlSafely('example.org')?.host, 'example.org');
      assert.equal(parseUrlSafely('http://test.co.uk:8080/foo')?.host, 'test.co.uk');
      assert.equal(parseUrlSafely(''), null);
      assert.equal(parseUrlSafely('   '), null);
      assert.equal(parseUrlSafely(null), null);
    });

    it('getRegistrableDomain extracts correct eTLD+1 for single and two-part TLDs', () => {
      assert.equal(getRegistrableDomain('portal.example.com'), 'example.com');
      assert.equal(getRegistrableDomain('sub.deep.login.bank.co.uk'), 'bank.co.uk');
      assert.equal(getRegistrableDomain('retail.onlinesbi.sbi.co.in'), 'sbi.co.in');
      assert.equal(getRegistrableDomain('google.com'), 'google.com');
    });

    it('levenshteinDistance calculates accurate edit distances', () => {
      assert.equal(levenshteinDistance('paypal', 'paypal'), 0);
      assert.equal(levenshteinDistance('paypal', 'paypa1'), 1);
      assert.equal(levenshteinDistance('microsoft', 'micros0ft'), 1);
      assert.equal(levenshteinDistance('apple', 'aple'), 1);
      assert.equal(levenshteinDistance('google', 'g00gle'), 2);
    });

    it('isIPv4Literal identifies valid IPv4 addresses', () => {
      assert.equal(isIPv4Literal('192.168.1.1'), true);
      assert.equal(isIPv4Literal('8.8.8.8'), true);
      assert.equal(isIPv4Literal('104.244.42.1'), true);
      assert.equal(isIPv4Literal('example.com'), false);
      assert.equal(isIPv4Literal('999.1.1.1'), false);
      assert.equal(isIPv4Literal('192.168.1'), false);
    });

    it('isIPv6Literal identifies IPv6 literals', () => {
      assert.equal(isIPv6Literal('[2001:db8::1]'), true);
      assert.equal(isIPv6Literal('2001:db8::1'), true);
      assert.equal(isIPv6Literal('example.com'), false);
    });

    it('hasHomographOrPunycode detects punycode and unicode confusion', () => {
      assert.equal(hasHomographOrPunycode('xn--pple-43d.com'), true);
      assert.equal(hasHomographOrPunycode('google.com'), false);
      assert.equal(hasHomographOrPunycode('gооgle.com'), true); // Cyrillic 'о'
    });

    it('checkBrandLookalike flags deceptive domain bases and subdomain spoofs', () => {
      const match1 = checkBrandLookalike('paypa1.com', 'paypa1.com');
      assert.equal(match1?.isLookalike, true);
      assert.equal(match1?.brand, 'paypal');

      const match2 = checkBrandLookalike('paypal.com.attacker.net', 'attacker.net');
      assert.equal(match2?.isLookalike, true);
      assert.equal(match2?.brand, 'paypal');

      // Exact legitimate brand is not a lookalike
      const match3 = checkBrandLookalike('paypal.com', 'paypal.com');
      assert.equal(match3, null);
    });
  });

  describe('Individual Detection Signals', () => {
    it('Signal: Raw IP Address Host triggers 30 points and Suspicious', () => {
      const res = analyzeUrl('http://192.168.1.10/login');
      assert.ok(res.signals.some(s => s.id === 'raw_ip_host'));
      assert.ok(res.score >= 30);
      assert.notEqual(res.verdict, 'Safe');
    });

    it('Signal: Punycode / IDN Homograph triggers 25 points', () => {
      const res = analyzeUrl('https://xn--gogle-pra.com');
      assert.ok(res.signals.some(s => s.id === 'punycode_homograph'));
      assert.equal(res.signals.find(s => s.id === 'punycode_homograph')?.points, 25);
    });

    it('Signal: Brand look-alike triggers 35 points and Suspicious', () => {
      const res = analyzeUrl('https://micros0ft.com');
      assert.ok(res.signals.some(s => s.id === 'brand_lookalike'));
      assert.equal(res.signals.find(s => s.id === 'brand_lookalike')?.points, 35);
      assert.equal(res.verdict, 'Suspicious');
    });

    it('Signal: Suspicious TLD triggers 10 points', () => {
      const res = analyzeUrl('https://daily-report.zip');
      assert.ok(res.signals.some(s => s.id === 'suspicious_tld'));
      assert.equal(res.signals.find(s => s.id === 'suspicious_tld')?.points, 10);
    });

    it('Signal: Structure oddities (@ symbol, excessive hyphens, long host)', () => {
      const resHyphens = analyzeUrl('https://secure-login-account-update-portal.com');
      assert.ok(resHyphens.signals.some(s => s.id === 'structure_oddities'));

      const resAt = analyzeUrl('https://legit.com@phishing-target.com');
      assert.ok(resAt.signals.some(s => s.id === 'structure_oddities'));
    });

    it('Signal: No HTTPS triggers 15 points', () => {
      const res = analyzeUrl('http://unencrypted-portal.org');
      assert.ok(res.signals.some(s => s.id === 'no_https'));
      assert.equal(res.signals.find(s => s.id === 'no_https')?.points, 15);
    });

    it('Signal: Credential form posting to external domain triggers 30 points', () => {
      const res = analyzeUrl('https://mybank-portal.example.com/login', {
        passwordForm: true,
        formTargetHost: 'credential-stealer.xyz'
      });
      assert.ok(res.signals.some(s => s.id === 'form_cross_domain'));
      assert.equal(res.signals.find(s => s.id === 'form_cross_domain')?.points, 30);
    });

    it('Signal: Urgency language triggers 10 points', () => {
      const res = analyzeUrl('https://notification-center.org', {
        keywordHits: ['verify account', 'one-time password']
      });
      assert.ok(res.signals.some(s => s.id === 'urgency_language'));
      assert.equal(res.signals.find(s => s.id === 'urgency_language')?.points, 10);
    });

    it('Signal: Newly registered domain triggers 25 points', () => {
      const res = analyzeUrl('https://brand-promo.com', {}, {
        domainAgeDays: 7
      });
      assert.ok(res.signals.some(s => s.id === 'new_domain'));
      assert.equal(res.signals.find(s => s.id === 'new_domain')?.points, 25);
    });

    it('Signal: Weak DNS on lookalike triggers 5 points', () => {
      const res = analyzeUrl('https://paypa1.com', {}, {
        hasMxRecords: false
      });
      assert.ok(res.signals.some(s => s.id === 'weak_dns_hygiene'));
    });

    it('Signal: Safe Browsing match forces Dangerous verdict regardless of score', () => {
      const res = analyzeUrl('https://unknown-domain.org', {}, {
        safeBrowsingMatch: true
      });
      assert.equal(res.verdict, 'Dangerous');
      assert.equal(res.score, 100);
      assert.ok(res.signals.some(s => s.id === 'safe_browsing_match'));
    });
  });

  describe('Known-Good Popular Sites (Section 12 Acceptance Criteria: 100% Safe)', () => {
    const knownGood = [
      'https://google.com',
      'https://github.com',
      'https://microsoft.com',
      'https://apple.com',
      'https://amazon.com',
      'https://wikipedia.org',
      'https://paypal.com',
      'https://netflix.com',
      'https://sbi.co.in',
      'https://linkedin.com'
    ];

    for (const url of knownGood) {
      it(`evaluates known-good site "${url}" as Safe`, () => {
        const start = performance.now();
        const res = analyzeUrl(url);
        const durationMs = performance.now() - start;

        assert.equal(res.verdict, 'Safe', `Expected ${url} to be Safe, got ${res.verdict} (Score: ${res.score})`);
        assert.ok(res.score < 30, `Score should be below 30, was ${res.score}`);
        assert.ok(durationMs < 50, `Evaluation should take < 50ms, took ${durationMs.toFixed(2)}ms`);
      });
    }
  });

  describe('Synthetic Malicious Patterns (Section 12 Acceptance Criteria: >= 8/10 Suspicious or Dangerous)', () => {
    const maliciousTestCases = [
      {
        name: 'Direct IPv4 host with HTTP',
        url: 'http://192.168.1.100/login',
        expectedNot: 'Safe'
      },
      {
        name: 'Punycode IDN homograph impersonation',
        url: 'https://xn--pple-43d.com',
        expectedNot: 'Safe'
      },
      {
        name: 'PayPal brand typo-squatting',
        url: 'https://paypa1.com/verify',
        expectedNot: 'Safe'
      },
      {
        name: 'Microsoft look-alike on suspicious .xyz TLD',
        url: 'https://micros0ft-support.xyz/login',
        expectedNot: 'Safe'
      },
      {
        name: 'Suspicious TLD + unencrypted HTTP + urgency keywords',
        url: 'http://secure-update-account.top/login',
        pageSignals: { keywordHits: ['urgent action', 'verify your account'] },
        expectedNot: 'Safe'
      },
      {
        name: 'Google spoofed in subdomain of foreign attacker domain',
        url: 'https://login.google.com.verify-security-now.com/auth',
        expectedNot: 'Safe'
      },
      {
        name: 'Netflix lookalike on .xyz with cross-domain credential form',
        url: 'http://netflix-billing-update.xyz/verify',
        pageSignals: { passwordForm: true, formTargetHost: 'evil-stealer.com' },
        expectedVerdict: 'Dangerous'
      },
      {
        name: 'Disposable domain with multiple hyphens + OTP phishing form',
        url: 'https://account-verify-login-update-support.click/otp',
        pageSignals: { passwordForm: true, formTargetHost: 'remote-collector.net', keywordHits: ['enter otp'] },
        expectedVerdict: 'Dangerous'
      },
      {
        name: 'SBI brand lookalike on abused .buzz TLD',
        url: 'https://sbi-portal-verify.buzz/kyc',
        expectedNot: 'Safe'
      },
      {
        name: 'Google Safe Browsing confirmed malicious threat match',
        url: 'https://threat-site.com/malware',
        externalSignals: { safeBrowsingMatch: true },
        expectedVerdict: 'Dangerous'
      }
    ];

    let suspiciousOrDangerousCount = 0;

    for (const tc of maliciousTestCases) {
      it(`detects malicious pattern: ${tc.name}`, () => {
        const start = performance.now();
        const res = analyzeUrl(tc.url, tc.pageSignals || {}, tc.externalSignals || {});
        const durationMs = performance.now() - start;

        if (tc.expectedVerdict) {
          assert.equal(res.verdict, tc.expectedVerdict, `Expected ${tc.url} to be ${tc.expectedVerdict}, got ${res.verdict}`);
        }
        if (tc.expectedNot) {
          assert.notEqual(res.verdict, tc.expectedNot, `Expected ${tc.url} not to be ${tc.expectedNot}, but was ${res.verdict}`);
        }

        if (res.verdict === 'Suspicious' || res.verdict === 'Dangerous') {
          suspiciousOrDangerousCount++;
        }

        assert.ok(durationMs < 50, `Evaluation should take < 50ms, took ${durationMs.toFixed(2)}ms`);
      });
    }

    it('verifies acceptance criteria: at least 8 of 10 synthetic threats flagged as Suspicious or Dangerous', () => {
      assert.ok(
        suspiciousOrDangerousCount >= 8,
        `Expected at least 8/10 malicious patterns to be caught, caught ${suspiciousOrDangerousCount}/10`
      );
    });
  });

  describe('Performance and Offline Guarantees', () => {
    it('executes analysis synchronously in well under 1000ms locally with no network calls', () => {
      const iterations = 100;
      const start = performance.now();
      for (let i = 0; i < iterations; i++) {
        analyzeUrl('https://paypa1-security-check.xyz/login', {
          passwordForm: true,
          formTargetHost: 'evil.com',
          keywordHits: ['otp']
        });
      }
      const totalMs = performance.now() - start;
      const avgMs = totalMs / iterations;

      assert.ok(avgMs < 5, `Expected average execution < 5ms, took ${avgMs.toFixed(2)}ms`);
    });
  });

});
