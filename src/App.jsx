import React, { useEffect, useState } from "react";

const COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#10b981"];

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "dark");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({ total: 0, breached: 0, safe: 0, averageStrength: 0 });
  const [history, setHistory] = useState([]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  async function refresh() {
    try {
      const [s, h] = await Promise.all([
        fetch("/api/scans/stats").then((r) => r.json()),
        fetch("/api/scans/history").then((r) => r.json()),
      ]);
      setStats(s);
      setHistory(h.scans || []);
    } catch {}
  }
  useEffect(() => {
    refresh();
  }, []);

  async function check(e) {
    e.preventDefault();
    if (!password) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch("/api/password/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      setResult(data);
      refresh();
    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <header className="nav">
        <h1>🔐 SecurePass</h1>
        <button className="ghost" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          {theme === "dark" ? "☀️ Light" : "🌙 Dark"}
        </button>
      </header>

      <main>
        <section className="card">
          <h2>Password Breach & Strength Checker</h2>
          <p className="muted">
            Only the first 5 characters of the SHA-1 hash are sent to Have I Been Pwned. Your password is never stored.
          </p>
          <form onSubmit={check} className="row">
            <input
              type={show ? "text" : "password"}
              placeholder="Enter a password to test"
              value={password}
              maxLength={128}
              autoComplete="off"
              onChange={(e) => setPassword(e.target.value)}
            />
            <button type="button" className="ghost" onClick={() => setShow(!show)}>
              {show ? "Hide" : "Show"}
            </button>
            <button type="submit" disabled={loading || !password}>
              {loading ? "Checking..." : "Check"}
            </button>
          </form>
          {error && <p className="error">{error}</p>}

          {result && (
            <div className="result">
              <div className={`badge ${result.breached ? "bad" : "good"}`}>
                {result.breached
                  ? `⚠️ Found in ${result.pwnedCount.toLocaleString()} known breaches`
                  : "✅ Not found in known breaches"}
              </div>
              <div className="meter">
                {[0, 1, 2, 3, 4].map((i) => (
                  <span
                    key={i}
                    style={{ background: i <= result.strengthScore ? COLORS[result.strengthScore] : undefined }}
                  />
                ))}
              </div>
              <p>
                Strength: <strong>{result.strengthLabel}</strong> · Estimated crack time:{" "}
                <strong>{result.crackTime}</strong>
              </p>
              {result.warning && <p className="warn">{result.warning}</p>}
              {result.suggestions?.length > 0 && (
                <ul>
                  {result.suggestions.map((s) => (
                    <li key={s}>{s}</li>
                  ))}
                </ul>
              )}
              <p className="muted small">A clean result does not guarantee a password is safe.</p>
            </div>
          )}
        </section>

        <section className="stats">
          <div className="card stat"><b>{stats.total}</b><span>Total scans</span></div>
          <div className="card stat"><b>{stats.breached}</b><span>Breached</span></div>
          <div className="card stat"><b>{stats.safe}</b><span>Not found</span></div>
          <div className="card stat"><b>{stats.averageStrength}/4</b><span>Avg strength</span></div>
        </section>

        <section className="card">
          <h3>Recent scans</h3>
          {history.length === 0 ? (
            <p className="muted">No scans yet.</p>
          ) : (
            <table>
              <thead>
                <tr><th>Time</th><th>Strength</th><th>Breach count</th></tr>
              </thead>
              <tbody>
                {history.map((s, i) => (
                  <tr key={s._id || i}>
                    <td>{new Date(s.createdAt).toLocaleString()}</td>
                    <td>{s.strengthLabel}</td>
                    <td>{s.pwnedCount.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </main>
    </div>
  );
}
