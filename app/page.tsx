import Link from "next/link";

export default function Home() {
  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white">
      {/* Navigation */}
      <nav className="flex h-16 items-center justify-between border-b border-white/10 px-6 lg:px-10">
        <div className="text-xl font-bold tracking-tight">
          CODE<span className="text-gray-400">LAB</span>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/sign-in"
            className="rounded-lg px-4 py-2 text-sm text-gray-300 transition hover:bg-white/10 hover:text-white"
          >
            Sign In
          </Link>

          <Link
            href="/sign-up"
            className="rounded-lg bg-white px-4 py-2 text-sm font-medium text-black transition hover:bg-gray-200"
          >
            Get Started
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-6xl flex-col items-center justify-center px-6 text-center">
        <div className="mb-6 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-gray-400">
          Browser-based collaborative development
        </div>

        <h1 className="max-w-4xl text-5xl font-bold tracking-tight sm:text-6xl lg:text-7xl">
          Code together.
          <br />
          <span className="text-gray-400">Build together.</span>
        </h1>

        <p className="mt-6 max-w-2xl text-lg leading-8 text-gray-400">
          CODE LAB is a browser-based collaborative coding environment where
          developers can write, share, run, and track code together in real
          time.
        </p>

        {/* Primary Actions */}
        <div className="mt-10 flex flex-col gap-3 sm:flex-row">
          <Link
            href="/sign-up"
            className="rounded-xl bg-white px-7 py-3.5 font-semibold text-black transition hover:bg-gray-200"
          >
            Start Coding
          </Link>

          <button
            type="button"
            className="rounded-xl border border-white/15 px-7 py-3.5 font-semibold text-white transition hover:bg-white/10"
          >
            Explore CODE LAB
          </button>
        </div>

        {/* Core Features */}
        <div className="mt-24 grid w-full max-w-4xl grid-cols-1 gap-4 sm:grid-cols-3">
          <Feature
            title="Real-time"
            description="Edit code together with your team in the same workspace."
          />

          <Feature
            title="Browser-based"
            description="Open your development workspace from any supported browser."
          />

          <Feature
            title="Change History"
            description="Track who changed what and when throughout the project."
          />
        </div>
      </section>
    </main>
  );
}

function Feature({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-6 text-left transition hover:bg-white/[0.06]">
      <h2 className="text-lg font-semibold">{title}</h2>

      <p className="mt-2 text-sm leading-6 text-gray-400">{description}</p>
    </div>
  );
}