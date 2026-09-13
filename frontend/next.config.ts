import type { NextConfig } from "next";

/**
 * The console never reaches the broker from the browser.
 *
 * Every screen is a server component that reads `BROKER_API_BASE_URL` on the server and renders
 * finished markup. There is deliberately no `env` block here and no `NEXT_PUBLIC_` variable
 * anywhere: `next.config.ts`'s `env` inlines values into the client bundle, which would publish
 * the broker's internal address to every visitor and put a base URL that is meant to be an
 * infrastructure detail into page source. `src/test/boundary.test.ts` fails the build if either
 * slips back in.
 *
 * The same decision keeps tokens out of the browser. Nothing on these screens is a credential,
 * so there is nothing for a client-side XSS to read.
 */
const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
};

export default nextConfig;
