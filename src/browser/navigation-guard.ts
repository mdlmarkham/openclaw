import { hasProxyEnvConfigured } from "../infra/net/proxy-env.js";
import {
  isPrivateNetworkAllowedByPolicy,
  isSsrFConfirmRequiredByPolicy,
  isCloudMetadataAddress,
  resolvePinnedHostnameWithPolicy,
  type LookupFn,
  type SsrFPolicy,
  type SsrFConfirmationRequest,
} from "../infra/net/ssrf.js";

const NETWORK_NAVIGATION_PROTOCOLS = new Set(["http:", "https:"]);
const SAFE_NON_NETWORK_URLS = new Set(["about:blank"]);

function isAllowedNonNetworkNavigationUrl(parsed: URL): boolean {
  // Keep non-network navigation explicit; about:blank is the only allowed bootstrap URL.
  return SAFE_NON_NETWORK_URLS.has(parsed.href);
}

export class InvalidBrowserNavigationUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidBrowserNavigationUrlError";
  }
}

export type BrowserNavigationPolicyOptions = {
  ssrfPolicy?: SsrFPolicy;
};

export function withBrowserNavigationPolicy(
  ssrfPolicy?: SsrFPolicy,
): BrowserNavigationPolicyOptions {
  return ssrfPolicy ? { ssrfPolicy } : {};
}

export async function assertBrowserNavigationAllowed(
  opts: {
    url: string;
    lookupFn?: LookupFn;
  } & BrowserNavigationPolicyOptions,
): Promise<void> {
  const rawUrl = String(opts.url ?? "").trim();
  if (!rawUrl) {
    throw new InvalidBrowserNavigationUrlError("url is required");
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new InvalidBrowserNavigationUrlError(`Invalid URL: ${rawUrl}`);
  }

  if (!NETWORK_NAVIGATION_PROTOCOLS.has(parsed.protocol)) {
    if (isAllowedNonNetworkNavigationUrl(parsed)) {
      return;
    }
    throw new InvalidBrowserNavigationUrlError(
      `Navigation blocked: unsupported protocol "${parsed.protocol}"`,
    );
  }

  // Browser network stacks may apply env proxy routing at connect-time, which
  // can bypass strict destination-binding intent from pre-navigation DNS checks.
  // In strict mode, fail closed unless private-network navigation is explicitly
  // enabled by policy.
  if (hasProxyEnvConfigured() && !isPrivateNetworkAllowedByPolicy(opts.ssrfPolicy)) {
    throw new InvalidBrowserNavigationUrlError(
      "Navigation blocked: strict browser SSRF policy cannot be enforced while env proxy variables are set",
    );
  }

  await resolvePinnedHostnameWithPolicy(parsed.hostname, {
    lookupFn: opts.lookupFn,
    policy: opts.ssrfPolicy,
  });
}

/**
 * Best-effort post-navigation guard for final page URLs.
 * Only validates network URLs (http/https) and about:blank to avoid false
 * positives on browser-internal error pages (e.g. chrome-error://).
 */
export async function assertBrowserNavigationResultAllowed(
  opts: {
    url: string;
    lookupFn?: LookupFn;
  } & BrowserNavigationPolicyOptions,
): Promise<void> {
  const rawUrl = String(opts.url ?? "").trim();
  if (!rawUrl) {
    return;
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return;
  }
  if (
    NETWORK_NAVIGATION_PROTOCOLS.has(parsed.protocol) ||
    isAllowedNonNetworkNavigationUrl(parsed)
  ) {
    await assertBrowserNavigationAllowed(opts);
  }
}

/**
 * Thrown when browser navigation requires user confirmation.
 * Only occurs when ssrfPolicy.allowPrivateNetwork === "confirm".
 */
export class BrowserNavigationConfirmationNeededError extends Error {
  constructor(public readonly request: SsrFConfirmationRequest) {
    super(`Navigation to private network requires confirmation: ${request.destination}`);
    this.name = "BrowserNavigationConfirmationNeededError";
  }
}

/**
 * Result of checking if browser navigation needs confirmation.
 * Returns confirmation request if policy requires it, or throws if blocked.
 */
export async function checkBrowserNavigationNeedsConfirmation(
  opts: {
    url: string;
    lookupFn?: LookupFn;
    reason?: string;
    requestedBy?: string;
  } & BrowserNavigationPolicyOptions,
): Promise<SsrFConfirmationRequest | null> {
  // Fast path: if policy doesn't require confirmation, delegate to assert function
  if (!isSsrFConfirmRequiredByPolicy(opts.ssrfPolicy)) {
    await assertBrowserNavigationAllowed({
      url: opts.url,
      lookupFn: opts.lookupFn,
      ssrfPolicy: opts.ssrfPolicy,
    });
    return null;
  }

  const rawUrl = String(opts.url ?? "").trim();
  if (!rawUrl) {
    throw new InvalidBrowserNavigationUrlError("url is required");
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new InvalidBrowserNavigationUrlError(`Invalid URL: ${rawUrl}`);
  }

  if (!NETWORK_NAVIGATION_PROTOCOLS.has(parsed.protocol)) {
    if (isAllowedNonNetworkNavigationUrl(parsed)) {
      return null;
    }
    throw new InvalidBrowserNavigationUrlError(
      `Navigation blocked: unsupported protocol "${parsed.protocol}"`,
    );
  }

  // Check for cloud metadata endpoints (always blocked)
  if (isCloudMetadataAddress(parsed.hostname)) {
    throw new InvalidBrowserNavigationUrlError(
      `Navigation blocked: cloud metadata endpoint "${parsed.hostname}" is not allowed`,
    );
  }

  // With proxy env and "confirm" policy, we still need confirmation
  if (hasProxyEnvConfigured()) {
    return {
      destination: parsed.hostname,
      port: parsed.port
        ? Number.parseInt(parsed.port, 10)
        : parsed.protocol === "https:"
          ? 443
          : 80,
      protocol: parsed.protocol.slice(0, -1) as "http" | "https",
      reason: opts.reason ?? "Private network access via proxy environment",
      requestedBy: opts.requestedBy,
      requestedAt: Date.now(),
    };
  }

  // Resolve hostname to check if private
  try {
    await resolvePinnedHostnameWithPolicy(parsed.hostname, {
      lookupFn: opts.lookupFn,
      policy: { allowPrivateNetwork: false }, // Block if private, need confirmation
    });
    // If we get here, it's not private - allow without confirmation
    return null;
  } catch {
    // It's a private address - return confirmation request
    return {
      destination: parsed.hostname,
      port: parsed.port
        ? Number.parseInt(parsed.port, 10)
        : parsed.protocol === "https:"
          ? 443
          : 80,
      protocol: parsed.protocol.slice(0, -1) as "http" | "https",
      reason: opts.reason ?? "Private network address",
      requestedBy: opts.requestedBy,
      requestedAt: Date.now(),
    };
  }
}
