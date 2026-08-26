"use client";

import { useState } from "react";
import { createProject } from "@/app/actions/projects";
import { useRouter } from "next/navigation";

export function CreateProjectForm() {
  const router = useRouter();

  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setError("");
    setLoading(true);

    try {
      await createProject(name);

      setName("");
      setOpen(false);

      router.refresh();
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Failed to create project."
      );
    } finally {
      setLoading(false);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="rounded-xl bg-white px-5 py-3 text-sm font-semibold text-black transition hover:bg-gray-200"
      >
        + New Project
      </button>
    );
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="w-full max-w-sm rounded-2xl border border-white/10 bg-white/[0.03] p-4"
    >
      <label
        htmlFor="project-name"
        className="text-sm font-medium text-gray-300"
      >
        Project name
      </label>

      <input
        id="project-name"
        type="text"
        value={name}
        onChange={(event) => setName(event.target.value)}
        placeholder="My Python Project"
        autoFocus
        disabled={loading}
        className="mt-2 w-full rounded-xl border border-white/10 bg-black px-4 py-3 text-sm text-white outline-none placeholder:text-gray-600 focus:border-white/30"
      />

      {error && (
        <p className="mt-2 text-sm text-red-400">
          {error}
        </p>
      )}

      <div className="mt-4 flex gap-2">
        <button
          type="submit"
          disabled={loading}
          className="rounded-xl bg-white px-4 py-2 text-sm font-semibold text-black disabled:opacity-50"
        >
          {loading ? "Creating..." : "Create"}
        </button>

        <button
          type="button"
          onClick={() => {
            setOpen(false);
            setName("");
            setError("");
          }}
          disabled={loading}
          className="rounded-xl border border-white/10 px-4 py-2 text-sm text-gray-300"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}