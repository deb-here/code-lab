import { SignIn } from "@clerk/nextjs";

export default function Page() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-[#0a0a0a] px-6">
      <SignIn
        forceRedirectUrl="/dashboard"
        fallbackRedirectUrl="/dashboard"
      />
    </main>
  );
}