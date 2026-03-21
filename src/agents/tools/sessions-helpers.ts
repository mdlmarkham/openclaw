export type {
  AgentToAgentPolicy,
  SessionAccessAction,
  SessionAccessResult,
  SessionToolsVisibility,
} from "./sessions-access.js";
export {
  createAgentToAgentPolicy,
  createSessionVisibilityGuard,
  resolveEffectiveSessionToolsVisibility,
  resolveSandboxSessionToolsVisibility,
  resolveSandboxedSessionToolContext,
  resolveSessionToolsVisibility,
} from "./sessions-access.js";
import { resolveSandboxedSessionToolContext } from "./sessions-access.js";
export type { SessionReferenceResolution } from "./sessions-resolution.js";
export {
  isRequesterSpawnedSessionVisible,
  isResolvedSessionVisibleToRequester,
  listSpawnedSessionKeys,
  looksLikeSessionId,
  looksLikeSessionKey,
  resolveDisplaySessionKey,
  resolveInternalSessionKey,
  resolveMainSessionAlias,
  resolveSessionReference,
  resolveVisibleSessionReference,
  shouldResolveSessionIdInput,
  shouldVerifyRequesterSpawnedSessionVisibility,
} from "./sessions-resolution.js";
import { type OpenClawConfig, loadConfig } from "../../config/config.js";
import { extractTextFromChatContent } from "../../shared/chat-content.js";
import { sanitizeUserFacingText } from "../pi-embedded-helpers.js";
import {
  stripDowngradedToolCallText,
  stripMinimaxToolCallXml,
  stripModelSpecialTokens,
  stripThinkingTagsFromText,
} from "../pi-embedded-utils.js";

export type SessionKind = "main" | "group" | "cron" | "hook" | "node" | "other";

export type SessionListDeliveryContext = {
  channel?: string;
  to?: string;
  accountId?: string;
};

export type SessionRunStatus = "running" | "done" | "failed" | "killed" | "timeout";

export type SessionListRow = {
  key: string;
  kind: SessionKind;
  channel: string;
  label?: string;
  displayName?: string;
  deliveryContext?: SessionListDeliveryContext;
  updatedAt?: number | null;
  sessionId?: string;
  model?: string;
  contextTokens?: number | null;
  totalTokens?: number | null;
  estimatedCostUsd?: number;
  status?: SessionRunStatus;
  startedAt?: number;
  endedAt?: number;
  runtimeMs?: number;
  childSessions?: string[];
  thinkingLevel?: string;
  verboseLevel?: string;
  systemSent?: boolean;
  abortedLastRun?: boolean;
  sendPolicy?: string;
  lastChannel?: string;
  lastTo?: string;
  lastAccountId?: string;
  transcriptPath?: string;
  messages?: unknown[];
};

function normalizeKey(value?: string) {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

export function resolveSessionToolContext(opts?: {
  agentSessionKey?: string;
  sandboxed?: boolean;
  config?: OpenClawConfig;
}) {
  const cfg = opts?.config ?? loadConfig();
  return {
    cfg,
    ...resolveSandboxedSessionToolContext({
      cfg,
      agentSessionKey: opts?.agentSessionKey,
      sandboxed: opts?.sandboxed,
    }),
  };
}

export function classifySessionKind(params: {
  key: string;
  gatewayKind?: string | null;
  alias: string;
  mainKey: string;
}): SessionKind {
  const key = params.key;
  if (key === params.alias || key === params.mainKey) {
    return "main";
  }
  if (key.startsWith("cron:")) {
    return "cron";
  }
  if (key.startsWith("hook:")) {
    return "hook";
  }
  if (key.startsWith("node-") || key.startsWith("node:")) {
    return "node";
  }
  if (params.gatewayKind === "group") {
    return "group";
  }
  if (key.includes(":group:") || key.includes(":channel:")) {
    return "group";
  }
  return "other";
}

export function deriveChannel(params: {
  key: string;
  kind: SessionKind;
  channel?: string | null;
  lastChannel?: string | null;
}): string {
  if (params.kind === "cron" || params.kind === "hook" || params.kind === "node") {
    return "internal";
  }
  const channel = normalizeKey(params.channel ?? undefined);
  if (channel) {
    return channel;
  }
  const lastChannel = normalizeKey(params.lastChannel ?? undefined);
  if (lastChannel) {
    return lastChannel;
  }
  const parts = params.key.split(":").filter(Boolean);
  if (parts.length >= 3 && (parts[1] === "group" || parts[1] === "channel")) {
    return parts[0];
  }
  return "unknown";
}

export function stripToolMessages(messages: unknown[]): unknown[] {
  return messages.filter((msg) => {
    if (!msg || typeof msg !== "object") {
      return true;
    }
    const role = (msg as { role?: unknown }).role;
    return role !== "toolResult" && role !== "tool";
  });
}

/**
 * Sanitize text content to strip tool call markers and thinking tags.
 * This ensures user-facing text doesn't leak internal tool representations.
 */
export function sanitizeTextContent(text: string): string {
  if (!text) {
    return text;
  }
  return stripThinkingTagsFromText(
    stripDowngradedToolCallText(stripModelSpecialTokens(stripMinimaxToolCallXml(text))),
  );
}

export function extractAssistantText(message: unknown): string | undefined {
  if (!message || typeof message !== "object") {
    return undefined;
  }
  if ((message as { role?: unknown }).role !== "assistant") {
    return undefined;
  }
  const content = (message as { content?: unknown }).content;
  if (!Array.isArray(content)) {
    return undefined;
  }
  const joined =
    extractTextFromChatContent(content, {
      sanitizeText: sanitizeTextContent,
      joinWith: "",
      normalizeText: (text) => text.trim(),
    }) ?? "";
  const stopReason = (message as { stopReason?: unknown }).stopReason;
  // Gate on stopReason only — a non-error response with a stale/background errorMessage
  // should not have its content rewritten with error templates (#13935).
  const errorContext = stopReason === "error";

  return joined ? sanitizeUserFacingText(joined, { errorContext }) : undefined;
}

/**
 * Check if a session key is valid agent session key format.
 * Agent session keys match pattern: agent:agentid:label
 * This is a quick format check, use validateAgentSessionKey for full validation.
 */
export function isAgentSessionKeyRef(ref: string): boolean {
  return typeof ref === "string" && ref.startsWith("agent:") && ref.split(":").length === 3;
}

// ============================================================================
// A2A Security Validation Functions
// ============================================================================

/** Maximum input size for A2A calls (1MB) */
export const MAX_A2A_INPUT_SIZE = 1_000_000;

/** Maximum agent ID length */
const MAX_AGENT_ID_LENGTH = 64;

/** Maximum skill name length */
const MAX_SKILL_NAME_LENGTH = 128;

/** Valid agent ID pattern: lowercase alphanumeric, dash, underscore */
const AGENT_ID_PATTERN = /^[a-z0-9_-]+$/;

/** Valid skill name pattern: alphanumeric, dash, underscore (case preserved) */
const SKILL_NAME_PATTERN = /^[a-zA-Z0-9_-]+$/;

/** Valid session key pattern: agent:agentid:label (all lowercase) */
const SESSION_KEY_PATTERN = /^agent:[a-z0-9_-]+:[a-z0-9_-]+$/;

/**
 * Validate and normalize an agent ID.
 * - Converts to lowercase
 * - Rejects path traversal attempts
 * - Rejects special characters
 * - Enforces length limits
 */
export function validateAgentId(agentId: string): string {
  if (!agentId || typeof agentId !== "string") {
    throw new Error("Agent ID cannot be empty");
  }

  const trimmed = agentId.trim();
  if (!trimmed) {
    throw new Error("Agent ID cannot be empty");
  }

  // Check for null bytes
  if (trimmed.includes("\x00")) {
    throw new Error("Agent ID contains invalid characters");
  }

  // Check length
  if (trimmed.length > MAX_AGENT_ID_LENGTH) {
    throw new Error(`Agent ID too long (max ${MAX_AGENT_ID_LENGTH} characters)`);
  }

  // Normalize to lowercase
  const normalized = trimmed.toLowerCase();

  // Check for path traversal patterns
  if (normalized.includes("..") || normalized.includes("/") || normalized.includes("\\")) {
    throw new Error("Agent ID contains invalid characters");
  }

  // Validate pattern
  if (!AGENT_ID_PATTERN.test(normalized)) {
    throw new Error(
      "Agent ID must contain only lowercase letters, numbers, dashes, and underscores",
    );
  }

  return normalized;
}

/**
 * Validate a skill name.
 * - Preserves case (unlike agent ID)
 * - Rejects path traversal attempts
 * - Rejects special characters
 * - Enforces length limits
 */
export function validateSkillName(skillName: string): string {
  if (!skillName || typeof skillName !== "string") {
    throw new Error("Skill name cannot be empty");
  }

  const trimmed = skillName.trim();
  if (!trimmed) {
    throw new Error("Skill name cannot be empty");
  }

  // Check for null bytes
  if (trimmed.includes("\x00")) {
    throw new Error("Skill name contains invalid characters");
  }

  // Check length
  if (trimmed.length > MAX_SKILL_NAME_LENGTH) {
    throw new Error(`Skill name too long (max ${MAX_SKILL_NAME_LENGTH} characters)`);
  }

  // Check for path traversal patterns
  if (trimmed.includes("..") || trimmed.includes("/") || trimmed.includes("\\")) {
    throw new Error("Skill name contains invalid characters");
  }

  // Check for shell command patterns
  if (trimmed.includes(" ") && /[;&|`$()]/.test(trimmed)) {
    throw new Error("Skill name contains invalid characters");
  }

  // Validate pattern (case preserved)
  if (!SKILL_NAME_PATTERN.test(trimmed)) {
    throw new Error("Skill name must contain only letters, numbers, dashes, and underscores");
  }

  return trimmed;
}

/**
 * Validate an agent session key.
 * - Must match pattern: agent:agentid:label
 * - All lowercase
 * - Rejects path traversal
 */
export function validateAgentSessionKey(sessionKey: string): string {
  if (!sessionKey || typeof sessionKey !== "string") {
    throw new Error("Session key cannot be empty");
  }

  const trimmed = sessionKey.trim();
  if (!trimmed) {
    throw new Error("Session key cannot be empty");
  }

  // Check for null bytes
  if (trimmed.includes("\x00")) {
    throw new Error("Session key contains invalid characters");
  }

  // Enforce lowercase
  if (trimmed !== trimmed.toLowerCase()) {
    throw new Error("Session key must be lowercase");
  }

  // Check for path traversal
  if (trimmed.includes("..") || trimmed.includes("/") || trimmed.includes("\\")) {
    throw new Error("Session key contains invalid characters");
  }

  // Validate pattern
  if (!SESSION_KEY_PATTERN.test(trimmed)) {
    throw new Error("Session key must match pattern: agent:agentid:label");
  }

  return trimmed;
}

/**
 * Validate input size for A2A calls.
 * @param input - The input to validate
 * @param maxSize - Maximum size in bytes (defaults to MAX_A2A_INPUT_SIZE)
 * @throws Error if input exceeds max size
 */
export function validateInputSize(input: unknown, maxSize: number = MAX_A2A_INPUT_SIZE): void {
  let size: number;

  try {
    size = JSON.stringify(input).length;
  } catch {
    // If it can't be stringified, estimate based on type
    if (typeof input === "string") {
      size = input.length;
    } else if (typeof input === "object" && input !== null) {
      // Rough estimate for objects
      size = Object.keys(input).length * 100;
    } else {
      size = 0;
    }
  }

  if (size > maxSize) {
    throw new Error(`Input too large: ${size} bytes exceeds max ${maxSize} bytes`);
  }
}

/**
 * Bound a confidence value to the range [0, 1].
 * Returns 0.5 for non-numeric, NaN, or infinity values.
 */
export function boundConfidence(confidence: unknown): number {
  // Handle non-numeric values
  if (typeof confidence !== "number") {
    return 0.5;
  }

  // Handle NaN and Infinity
  if (!Number.isFinite(confidence)) {
    return 0.5;
  }

  // Clamp to [0, 1]
  if (confidence < 0) {
    return 0;
  }
  if (confidence > 1) {
    return 1;
  }

  return confidence;
}

/**
 * Check A2A policy for agent-to-agent calls.
 * Returns { allowed: true } if the call is permitted.
 * Returns { allowed: false, error: string } if denied.
 */
export function checkA2APolicy(
  cfg: OpenClawConfig,
  requesterAgentId: string,
  targetAgentId: string,
): { allowed: true } | { allowed: false; error: string } {
  // Self-call is handled by the caller (agent-call-tool.ts)
  // but we still check it here for completeness
  if (requesterAgentId === targetAgentId) {
    return {
      allowed: false,
      error: "Self-call not allowed: agent cannot invoke itself (infinite loop prevention)",
    };
  }

  // Check if A2A is enabled
  const routingA2A = cfg.tools?.agentToAgent;
  if (!routingA2A?.enabled) {
    return {
      allowed: false,
      error: "Agent-to-agent calls are disabled. Set tools.agentToAgent.enabled=true to enable.",
    };
  }

  // Check allowlist
  const allowPatterns = Array.isArray(routingA2A.allow) ? routingA2A.allow : [];

  // Empty allowlist = deny all
  if (allowPatterns.length === 0) {
    return {
      allowed: false,
      error: "No agents in A2A allowlist. Add agent IDs or '*' to tools.agentToAgent.allow.",
    };
  }

  // Check if both requester and target match the allowlist
  const matchesPattern = (agentId: string, pattern: string): boolean => {
    const raw = String(pattern ?? "").trim();
    if (!raw) {
      return false;
    }
    if (raw === "*") {
      return true;
    }
    if (!raw.includes("*")) {
      return raw === agentId;
    }
    const escaped = raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`^${escaped.replaceAll("\\*", ".*")}$`, "i");
    return re.test(agentId);
  };

  const requesterAllowed = allowPatterns.some((p) => matchesPattern(requesterAgentId, p));
  const targetAllowed = allowPatterns.some((p) => matchesPattern(targetAgentId, p));

  if (!requesterAllowed) {
    return {
      allowed: false,
      error: `Agent '${requesterAgentId}' is not in the A2A allowlist.`,
    };
  }

  if (!targetAllowed) {
    return {
      allowed: false,
      error: `Agent '${targetAgentId}' is not in the A2A allowlist.`,
    };
  }

  return { allowed: true };
}
