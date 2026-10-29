export const title = "What Sendable tells a domain owner to do next";

// Two regions: what the domain publishes, and what its senders are doing.
// They move independently, which is the thing a reader needs to see.
export const state = (v: any) => ({
  Record: record(v),
  Senders: senders(v),
});

function record(v: any): string {
  if (v.policy === "none") return "Not enforcing";
  const all = v.pct === 100;
  if (v.policy === "quarantine") return all ? "Quarantine, all mail" : "Quarantine, some mail";
  return all ? "Reject, all mail" : "Reject, some mail";
}

function senders(v: any): string {
  if (v.senders === "clean") return "All senders authenticate";
  if (v.senders === "unaligned") return "A real sender fails, nothing lost yet";
  return "My own mail is being blocked";
}

export const step = (action: string, from: any, to: any) => {
  switch (action) {
    case "TheOwnerFollowsTheAdvice":
      // Name the direction, which is what the reader is deciding about.
      return strength(to) > strength(from) ? "I tighten the record" : "I ease the record";
    case "ASenderBreaks":
      return "a sender of mine stops authenticating";
    case "ThePolicyStartsBlockingIt":
      return "my policy starts blocking that sender";
    case "TheSenderGetsAuthenticated":
      return "I authenticate that sender";
    default:
      return null; // the idle step at an end state adds nothing to read
  }
};

function strength(v: any): number {
  const rank = v.policy === "none" ? 0 : v.policy === "quarantine" ? 1 : 2;
  return rank * 1000 + (rank === 0 ? 0 : v.pct);
}

export const group = (v: any) =>
  v.senders === "bleeding" ? "Losing mail"
  : v.senders === "unaligned" ? "At risk"
  : v.policy === "reject" && v.pct === 100 ? "Fully protected"
  : "Safe to tighten";

export const colors = {
  "Losing mail": "orange",
  "At risk": "yellow",
  "Fully protected": "teal",
  "Safe to tighten": "blue",
};
