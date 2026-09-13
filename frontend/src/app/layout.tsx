import type { Metadata } from "next";

import { Nav } from "@/components/nav";

import "./globals.css";

export const metadata: Metadata = {
  title: "Authorization lab — agent-authz-broker",
  description:
    "An agent can request an action. It cannot manufacture the authority to perform one. " +
    "The security matrix, the delegation chain, the approvals, and the decision trail.",
};

/**
 * Every screen under this layout is a server component and none of them is interactive, so there
 * is no provider here and no client boundary anywhere in the app.
 */
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Nav />
        <main className="mx-auto max-w-7xl px-4 py-6">{children}</main>
      </body>
    </html>
  );
}
