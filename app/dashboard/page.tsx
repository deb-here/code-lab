import { UserButton } from "@clerk/nextjs";
import { auth } from "@clerk/nextjs/server";

export default async function Dashboard() {
  const { userId } = await auth();

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white">
      <nav className="flex h-16 items-center justify-between border-b border-white/10 px-6 lg:px-10">
        <div className="text-xl font-bold tracking-tight">
          CODE<span className="text-gray-400">LAB</span>
        </div>

        <UserButton />
      </nav>

      <section className="mx-auto max-w-6xl px-6 py-12">
        <p className="text-sm text-gray-500">Dashboard</p>

        <h1 className="mt-2 text-4xl font-bold tracking-tight">
          Welcome to CODE LAB
        </h1>

        <p className="mt-4 text-gray-400">
          Your collaborative coding workspace starts here.
        </p>

        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <button
            type="button"
            className="rounded-2xl border border-white/10 bg-white/[0.03] p-6 text-left transition hover:bg-white/[0.06]"
          >
            <h2 className="text-lg font-semibold">Create Project</h2>

            <p className="mt-2 text-sm leading-6 text-gray-400">
              Start a new collaborative coding project.
            </p>
          </button>

          <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-6">
            <h2 className="text-lg font-semibold">Your Projects</h2>

            <p className="mt-2 text-sm leading-6 text-gray-400">
              Your projects will appear here.
            </p>
          </div>

          <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-6">
            <h2 className="text-lg font-semibold">Activity</h2>

            <p className="mt-2 text-sm leading-6 text-gray-400">
              Project activity and change history will appear here.
            </p>
          </div>
        </div>

        <div className="mt-10 rounded-xl border border-white/10 bg-white/[0.02] p-4 text-xs text-gray-500">
          Authenticated user: {userId}
        </div>
      </section>
    </main>
  );
}