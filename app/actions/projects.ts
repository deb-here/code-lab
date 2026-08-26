"use server";

import { auth } from "@clerk/nextjs/server";
import { createClient } from "@/lib/supabase/server";

export async function createProject(name: string) {
  const { userId } = await auth();

  if (!userId) {
    throw new Error("You must be signed in to create a project.");
  }

  const projectName = name.trim();

  if (!projectName) {
    throw new Error("Project name is required.");
  }

  if (projectName.length > 100) {
    throw new Error("Project name is too long.");
  }

  const supabase = await createClient();

  const { data, error } = await supabase
    .from("projects")
    .insert({
      name: projectName,
      owner_id: userId,
    })
    .select()
    .single();

  if (error) {
    console.error("Failed to create project:", error);
    throw new Error("Failed to create project.");
  }

  return data;
}