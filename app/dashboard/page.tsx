import { auth } from "@clerk/nextjs/server";
import { UserButton } from "@clerk/nextjs";
import { createClient } from "@/lib/supabase/server";
import { CreateProjectForm } from "./create-project-form";

export default async function Dashboard() {
  const { userId } = await auth();

  if (!userId) {
    return null;
  }

  const supabase = await createClient();

  const { data: projects, error } = await supabase
    .from("projects")
    .select("id, name, created_at, updated_at")
    .eq("owner_id", userId)
    .order("updated_at", { ascending: false });

  if (error) {
    console.error("Failed to load projects:", error);
  }

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white">
      <nav className="flex h-16 items-center justify-between border-b border-white/10 px-6 lg:px-10">
        <div className="text-xl font-bold tracking-tight">
          CODE<span className="text-gray-400">LAB</span>
        </div>

        <UserButton />
      </nav>

      <section className="mx-auto max-w-6xl px-6 py-12">
        <div className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-sm text-gray-500">Dashboard</p>

            <h1 className="mt-2 text-4xl font-bold tracking-tight">
              My Projects
            </h1>

            <p className="mt-3 text-gray-400">
              Create and manage your CODE LAB projects.
            </p>
          </div>

          <CreateProjectForm />
        </div>

        {error ? (
          <div className="mt-10 rounded-xl border border-red-500/20 bg-red-500/5 p-5 text-sm text-red-400">
            Failed to load projects.
          </div>
        ) : projects && projects.length > 0 ? (
          <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {projects.map((project) => (
              <div
                key={project.id}
                className="rounded-2xl border border-white/10 bg-white/[0.03] p-6 transition hover:bg-white/[0.06]"
              >
                <h2 className="text-lg font-semibold">{project.name}</h2>

                <p className="mt-2 text-sm text-gray-500">
                  Created{" "}
                  {new Date(project.created_at).toLocaleDateString()}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <div className="mt-10 rounded-2xl border border-dashed border-white/10 p-12 text-center">
            <h2 className="text-xl font-semibold">No projects yet</h2>

            <p className="mt-2 text-sm text-gray-500">
              Create your first project to start building.
            </p>
          </div>
        )}
      </section>
    </main>
  );
}