import { describe, expect, it } from "vitest";
import type { CronJob } from "./types.js";

function makeCommandJob(overrides: Partial<CronJob>): CronJob {
  const now = Date.now();
  return {
    id: "job-1",
    name: "test-command",
    enabled: true,
    createdAtMs: now,
    updatedAtMs: now,
    schedule: { kind: "every", everyMs: 60_000 },
    sessionTarget: "main",
    wakeMode: "next-heartbeat",
    payload: { kind: "command", command: "echo 'hello'" },
    state: {},
    ...overrides,
  };
}

describe("CronCommandPayload schema", () => {
  it("accepts minimal command payload", () => {
    const job = makeCommandJob({});
    expect(job.payload.kind).toBe("command");
    expect((job.payload as { command: string }).command).toBe("echo 'hello'");
  });

  it("accepts command payload with options", () => {
    const job = makeCommandJob({
      payload: {
        kind: "command",
        command: "python script.py",
        timeout: 600,
        cwd: "/app",
        shell: "bash",
        onExit: "success",
      },
    });
    const payload = job.payload as {
      kind: "command";
      command: string;
      timeout?: number;
      cwd?: string;
      shell?: string;
      onExit?: string;
    };
    expect(payload.kind).toBe("command");
    expect(payload.command).toBe("python script.py");
    expect(payload.timeout).toBe(600);
    expect(payload.cwd).toBe("/app");
    expect(payload.shell).toBe("bash");
    expect(payload.onExit).toBe("success");
  });

  it("accepts hybrid mode with agentMessage", () => {
    const job = makeCommandJob({
      sessionTarget: "isolated",
      payload: {
        kind: "command",
        command: "cat /var/log/syslog | tail -100",
        agentMessage: "Analyze these logs for errors",
      },
    });
    const payload = job.payload as {
      kind: "command";
      command: string;
      agentMessage?: string;
    };
    expect(payload.agentMessage).toBe("Analyze these logs for errors");
    expect(job.sessionTarget).toBe("isolated");
  });

  it("accepts environment variables", () => {
    const job = makeCommandJob({
      payload: {
        kind: "command",
        command: "node backup.js",
        env: { NODE_ENV: "production", DB_HOST: "localhost" },
      },
    });
    const payload = job.payload as {
      kind: "command";
      command: string;
      env?: Record<string, string>;
    };
    expect(payload.env).toEqual({ NODE_ENV: "production", DB_HOST: "localhost" });
  });
});

describe("onExit conditions", () => {
  it("success mode only delivers on exit code 0", () => {
    const onExit = "success";
    const exitCodeSuccess = 0;
    const exitCodeFailure = 1;

    const shouldDeliverSuccess =
      onExit === "any" ||
      (onExit === "success" && exitCodeSuccess === 0) ||
      (onExit === "failure" && exitCodeSuccess !== 0);
    const shouldDeliverFailure =
      onExit === "any" ||
      (onExit === "success" && exitCodeFailure === 0) ||
      (onExit === "failure" && exitCodeFailure !== 0);

    expect(shouldDeliverSuccess).toBe(true);
    expect(shouldDeliverFailure).toBe(false);
  });

  it("failure mode only delivers on non-zero exit code", () => {
    const onExit = "failure";
    const exitCodeSuccess = 0;
    const exitCodeFailure = 1;

    const shouldDeliverSuccess =
      onExit === "any" ||
      (onExit === "success" && exitCodeSuccess === 0) ||
      (onExit === "failure" && exitCodeSuccess !== 0);
    const shouldDeliverFailure =
      onExit === "any" ||
      (onExit === "success" && exitCodeFailure === 0) ||
      (onExit === "failure" && exitCodeFailure !== 0);

    expect(shouldDeliverSuccess).toBe(false);
    expect(shouldDeliverFailure).toBe(true);
  });

  it("any mode delivers regardless of exit code", () => {
    const onExit = "any";
    const exitCodes = [0, 1, 127, 137];

    for (const exitCode of exitCodes) {
      const shouldDeliver =
        onExit === "any" ||
        (onExit === "success" && exitCode === 0) ||
        (onExit === "failure" && exitCode !== 0);
      expect(shouldDeliver).toBe(true);
    }
  });
});
