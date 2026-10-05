import { useState } from 'react';

// Change this to your real contact page, WhatsApp link or email.
const CONTACT_URL = '#contact';

const GRADE_TEXT = {
  'A+': 'Excellent. Every check passed.',
  A: 'Strong setup with only small gaps.',
  B: 'Good, but a few protections are missing.',
  C: 'Several important protections are missing.',
  D: 'Weak. Attackers have easy openings.',
  F: 'At risk. Basic protections are missing.',
};

function StatusIcon({ status }) {
  if (status === 'pass') {
    return (
      <svg className="icon icon-pass" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M5 12.5l4.5 4.5L19 7.5" />
      </svg>
    );
  }
  if (status === 'warn') {
    return (
      <svg className="icon icon-warn" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 7v6" />
        <path d="M12 17h.01" />
      </svg>
    );
  }
  return (
    <svg className="icon icon-fail" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M7 7l10 10M17 7L7 17" />
    </svg>
  );
}

function Result({ data }) {
  const failed = data.checks.filter((c) => c.status !== 'pass').length;
  const gradeClass = `grade grade-${data.grade.replace('+', 'plus')}`;
  return (
    <section className="result" aria-live="polite">
      <div className="summary">
        <div className={gradeClass} aria-label={`Grade ${data.grade}`}>{data.grade}</div>
        <div className="summary-text">
          <p className="eyebrow">{data.target}</p>
          <h2>{GRADE_TEXT[data.grade]}</h2>
          <p className="muted">
            Score {data.score}/100 · {data.checks.length - failed} of {data.checks.length} checks passed
          </p>
        </div>
      </div>

      <ul className="checks">
        {data.checks.map((c) => (
          <li key={c.id} className={`check check-${c.status}`}>
            <StatusIcon status={c.status} />
            <div>
              <h3>{c.title}</h3>
              <p className="muted">{c.detail}</p>
              {c.fix && (
                <p className="fix">
                  <span>Fix</span> {c.fix}
                </p>
              )}
            </div>
          </li>
        ))}
      </ul>

      {failed > 0 && (
        <div className="cta">
          <div>
            <h2>Want these fixed?</h2>
            <p>Noxora Lab can close these gaps for you, usually in a day. We build every website with all of these in place.</p>
          </div>
          <a className="button button-dark" href={CONTACT_URL}>Talk to us</a>
        </div>
      )}
    </section>
  );
}

export default function App() {
  const [url, setUrl] = useState('');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [data, setData] = useState(null);

  async function onSubmit(e) {
    e.preventDefault();
    setError('');
    setData(null);
    if (!consent) {
      setError('Please confirm you own this website or have permission to check it.');
      return;
    }
    setLoading(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, consent }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || 'Something went wrong. Please try again.');
      setData(body);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <header className="topbar">
        <span className="brand"><span className="brand-mark" />NOXORA LAB</span>
        <span className="muted mono">FREE TOOL</span>
      </header>

      <main>
        <section className="hero">
          <p className="eyebrow accent">Website security check</p>
          <h1>How secure is your website?</h1>
          <p className="lead">
            Check HTTPS, your SSL certificate and the security headers browsers use to protect your visitors. Results in seconds.
          </p>

          <form className="scan-form" onSubmit={onSubmit} noValidate>
            <label htmlFor="url" className="sr-only">Website address</label>
            <div className="input-row">
              <input
                id="url"
                type="text"
                inputMode="url"
                autoComplete="url"
                placeholder="yourbusiness.lk"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                maxLength={2048}
                required
              />
              <button className="button" type="submit" disabled={loading}>
                {loading ? 'Checking…' : 'Check my site'}
              </button>
            </div>
            <label className="consent">
              <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
              <span>I own this website or have permission to check it.</span>
            </label>
          </form>

          {error && <p className="error" role="alert">{error}</p>}
        </section>

        {data && <Result data={data} />}

        <section className="about">
          <h2>What this check does</h2>
          <p className="muted">
            It loads your homepage once, the same way a browser does, and reads the response. It does not attack, log in or
            test for vulnerabilities. A good grade here is a strong start, not a full security audit.
          </p>
        </section>
      </main>

      <footer className="footer muted mono">© Noxora Lab · Cyber &amp; software, built right.</footer>
    </div>
  );
}
