import { describe, test, expect } from "bun:test";
import { parseAgentDecision } from "./integrations";

describe("parseAgentDecision", () => {
  test("clean approve on its own line", () => {
    expect(parseAgentDecision("Analysis done.\nSCGUARD_DECISION: approve")).toBe("approved");
  });

  test("clean reject", () => {
    expect(parseAgentDecision("This is dangerous.\nSCGUARD_DECISION: reject")).toBe("rejected");
  });

  test("manual-review", () => {
    expect(parseAgentDecision("Unclear.\nSCGUARD_DECISION: manual-review")).toBe("manual-review");
  });

  test("case-insensitive decision", () => {
    expect(parseAgentDecision("SCGUARD_DECISION: APPROVE")).toBe("approved");
  });

  test("leading whitespace on decision line", () => {
    expect(parseAgentDecision("  SCGUARD_DECISION: approve  ")).toBe("approved");
  });

  test("no decision → manual-review (fail closed)", () => {
    expect(parseAgentDecision("I think this package looks fine.")).toBe("manual-review");
  });

  test("empty output → manual-review", () => {
    expect(parseAgentDecision("")).toBe("manual-review");
  });

  test("conflicting decisions → manual-review", () => {
    const output = "SCGUARD_DECISION: approve\nSCGUARD_DECISION: reject";
    expect(parseAgentDecision(output)).toBe("manual-review");
  });

  test("prose containing word 'approve' does NOT match", () => {
    const output = "I would approve this package based on my analysis.";
    expect(parseAgentDecision(output)).toBe("manual-review");
  });

  test("approve-ish suffix does NOT match", () => {
    // Token must match exactly; trailing words on the decision line are rejected.
    const output = "SCGUARD_DECISION: approve-ish";
    expect(parseAgentDecision(output)).toBe("manual-review");
  });

  test("last decision wins when same value repeated", () => {
    const output = "SCGUARD_DECISION: approve\nsome analysis\nSCGUARD_DECISION: approve";
    expect(parseAgentDecision(output)).toBe("approved");
  });

  test("decision embedded mid-line does NOT match", () => {
    const output = "result: SCGUARD_DECISION: approve yes";
    expect(parseAgentDecision(output)).toBe("manual-review");
  });
});
