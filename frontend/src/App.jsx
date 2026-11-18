const checks = [
  { label: "Controlled target policy", state: "Enabled" },
  { label: "Evidence-first analysis", state: "Enabled" },
  { label: "Project-defined score", state: "Configured" },
];

function App() {
  return (
    <main className="min-h-screen bg-slate-950 px-6 py-12 text-slate-100">
      <section className="mx-auto max-w-4xl">
        <p className="mb-3 text-sm font-semibold uppercase tracking-[0.25em] text-cyan-400">
          Foundations checkpoint
        </p>
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
          API Security &amp; Risk Intelligence
        </h1>
        <p className="mt-5 max-w-2xl text-lg leading-8 text-slate-300">
          A defensive, evidence-first workspace for testing APIs inside an explicitly controlled
          local lab.
        </p>

        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          {checks.map((check) => (
            <article key={check.label} className="rounded-xl border border-slate-800 bg-slate-900 p-5">
              <p className="text-sm text-slate-400">{check.label}</p>
              <p className="mt-3 text-xl font-semibold text-emerald-400">{check.state}</p>
            </article>
          ))}
        </div>

        <p className="mt-10 rounded-lg border border-amber-900/60 bg-amber-950/30 p-4 text-sm text-amber-200">
          The dashboard is currently a Milestone 1 skeleton. Vulnerable lab APIs and scanning
          features are added only in their scheduled milestones.
        </p>
      </section>
    </main>
  );
}

export default App;

