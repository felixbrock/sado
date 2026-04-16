# Problem

Probabilistic systems with access to privileged operations will cause harm to systems — mistakes are inevitable, and the operations are consequential

# [First Principles][first-principles]

[first-principles]: https://fs.blog/first-principles/

- Probabilistic systems make mistakes — this is inherent to how they work, not a bug to be fixed
- Probabilistic systems interact differently with systems than humans or deterministic programs do — they operate at machine speed, run in parallel, lack intrinsic intent, and derive their "purpose" from context
- Probabilistic systems can be hacked and used for destructive purposes — they can be deliberately steered toward harmful outcomes by adversaries
- The inputs to a probabilistic system are part of its attack surface — agent-supplied evidence (transcript, goal, activity) is potentially adversarial
- Privileged operations are irreversible or expensive to reverse
- **Context is the only basis for authorization** — there is no pre-established trust, no identity system, no credential; the decision is made from the evidence available at request time
- Existing security concepts (identity-based access control, static permissions, credential scoping) are insufficient for agents — they assume a trusted principal with intrinsic intent, which agents are not
- The cost of a false allow exceeds the cost of a false deny — blocking a legitimate operation causes friction; allowing a destructive one causes damage

# Decision variables

Variables to evaluate when deciding whether an agent should be authorized to perform a given action.

## Authority variables

Based on: https://notes.karlmcguinness.com/notes/agents-dont-need-your-passport-they-need-your-authority/

```json
[
  {
    "label": "Purpose / Mission Scope",
    "description": "Why was authority granted in the first place? The stated objective constrains what actions are legitimate.",
    "is_relevant": "relevant",
    "relevance_reasoning": "Every privileged command must be justified against a declared objective. Without purpose scoping, there's no basis to distinguish a legitimate apt install from a malicious one — the command alone is ambiguous.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "The goal must come from a source the agent cannot modify. An external task system (Linear ticket, CI job definition) or the original human instruction read directly from the session file on disk by the evaluator — not from a field the agent populates in its request. Agent-supplied SADO_GOAL is inherently tamperable."
  },
  {
    "label": "Mission Lifecycle",
    "description": "Is the task still active? Authority should end when the mission ends (e.g., ticket closed, program cancelled), independent of whether credentials are still technically valid.",
    "is_relevant": "relevant",
    "relevance_reasoning": "An agent whose task is complete should lose its admin authority immediately. A deploy agent that finished deploying 10 minutes ago has no business running systemctl commands now. Lifecycle awareness prevents stale authority from being exploited.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "Query the external task system directly (Linear API, Jira API, CI pipeline status) to check whether the task is still open. The agent must not be the one reporting its own mission status — it has an incentive to claim the mission is still active."
  },
  {
    "label": "Mandate Duration",
    "description": "The actual timeframe the task needs, distinct from token/credential expiry windows. A 3-hour task shouldn't get a 90-day token.",
    "is_relevant": "relevant",
    "relevance_reasoning": "Time-boxing admin access is a fundamental security principle. Even if the mission isn't formally 'done', there should be a maximum window. An agent running for 12 hours on what should be a 20-minute task is a signal something is wrong.",
    "evaluation_type": "deterministic",
    "secure_source_of_information": "The duration is set at grant time by the human or the orchestrating system, stored in a record the agent cannot modify. Enforcement is a system clock comparison against that record — no agent input needed."
  },
  {
    "label": "Originating Conditions",
    "description": "The circumstances that made the original human authorization legitimate. If those conditions change, the authority may no longer hold.",
    "is_relevant": "relevant",
    "relevance_reasoning": "A human authorized 'deploy to staging' — but the environment was reconfigured to point at production. The original grant is now dangerous under changed conditions. The system must track what made the grant valid, not just that it was granted.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "The original grant record — including the conditions under which it was issued — must be stored in a tamper-proof log written at authorization time. The evaluator reads this record directly, not a summary the agent provides. Current conditions are verified by querying live system state (e.g., environment config, infrastructure metadata)."
  },
  {
    "label": "Current Context Validity",
    "description": "Do the conditions that justified the initial grant still hold? This is a continuous check, not a one-time gate.",
    "is_relevant": "relevant",
    "relevance_reasoning": "Authorization is not a one-time gate. The conditions that made a grant safe at minute 0 may not hold at minute 15. Every privileged request should be re-evaluated against current state — not a cached decision.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "The evaluator must independently verify current state — read the session transcript from disk, query system state, check infrastructure metadata. The agent's description of 'what's happening right now' is not trustworthy. Cross-reference agent-supplied context against evaluator-accessible ground truth."
  },
  {
    "label": "Authority Provenance (Delegation Chain)",
    "description": "Can you trace a clear path from the acting agent back to the original human decision-maker? Every hop in the chain matters.",
    "is_relevant": "relevant",
    "relevance_reasoning": "Agents spawn sub-agents. An orchestrator agent delegates to a deploy agent which delegates to a config agent. When the config agent requests iptables access, you need to trace the chain back to the human who authorized the orchestrator — and verify every hop was legitimate.",
    "evaluation_type": "deterministic",
    "secure_source_of_information": "Cryptographically signed delegation tokens. Each hop in the chain signs the delegation with its own key, creating a verifiable certificate chain back to the human. The evaluator validates signatures — no trust in the agent's self-reported lineage."
  },
  {
    "label": "Scope Attenuation",
    "description": "Authority must decrease or stay constant through each delegation layer — never expand. Agent B, delegated by Agent A, cannot have more authority than Agent A.",
    "is_relevant": "relevant",
    "relevance_reasoning": "A human grants an agent permission to manage nginx. That agent spawns a helper. The helper should not be able to manage postgres. Authority can only narrow through delegation — never widen. Without this constraint, a single narrow grant can escalate through the agent graph.",
    "evaluation_type": "deterministic",
    "secure_source_of_information": "The scope is encoded in the delegation token at each hop — cryptographically bound so the delegating agent cannot issue a token with broader scope than its own. The evaluator compares the scope in the presented token against the parent token's scope. No agent input needed beyond presenting the token."
  },
  {
    "label": "Sub-delegation Legitimacy",
    "description": "Was the intermediate actor actually authorized to delegate further? Not all grants are transferable.",
    "is_relevant": "relevant",
    "relevance_reasoning": "Not all authority is transferable. A human may grant an agent admin access but not intend for that agent to pass it to arbitrary sub-agents. The system must distinguish 'you can do X' from 'you can authorize others to do X.'",
    "evaluation_type": "deterministic",
    "secure_source_of_information": "The original grant explicitly encodes whether sub-delegation is permitted (a 'delegatable' flag or equivalent). This is set by the human at grant time and cryptographically bound into the token. The evaluator checks the flag — the agent cannot retroactively grant itself delegation rights."
  },
  {
    "label": "Resource Discovery Context",
    "description": "What specific resources does the task require? Just-in-time, narrowly-scoped access rather than pre-enumerated broad permissions.",
    "is_relevant": "relevant",
    "relevance_reasoning": "Pre-enumerating all resources an agent might need leads to over-provisioning. The agent should discover what it needs at runtime and request access to specific resources in context. 'I need to restart nginx because the config I just wrote requires it' is a stronger grant basis than 'I might need to restart services.'",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "The resource request itself comes from the agent and cannot be avoided. But the justification is verified against the evaluator's own records: the audit log of prior actions (did the agent actually write an nginx config?), the session transcript read from disk, and the system's own observation of what changed. The agent says why — the evaluator independently checks whether that's true."
  },
  {
    "label": "Cross-Domain / Trust Boundary Hopping",
    "description": "When the authority chain crosses trust boundaries, re-evaluation is needed at each boundary.",
    "is_relevant": "relevant",
    "relevance_reasoning": "An agent authorized on the build server should not automatically carry that authority to the production server. Each trust boundary crossing — different machines, different cloud accounts, different security zones — requires re-evaluation of whether the authority still applies.",
    "evaluation_type": "deterministic",
    "secure_source_of_information": "Network topology, infrastructure tags, and security zone definitions are read from infrastructure configuration the agent cannot modify (cloud metadata APIs, network config, host classification systems). Boundary detection is based on the evaluator's knowledge of the environment, not the agent's claim about where it is."
  },
  {
    "label": "Behavioral Alignment",
    "description": "Are the agent's current actions consistent with the declared objective? Drift from the mission should trigger revocation.",
    "is_relevant": "relevant",
    "relevance_reasoning": "The strongest signal for revocation is behavioral drift. An agent granted admin access for 'set up the dev environment' that starts modifying firewall rules or reading /etc/shadow is acting outside its mandate. The pattern of actions, not just the current request, must be evaluated.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "The evaluator's own audit log of what the agent actually did — not the agent's self-reported activity. The privilege broker records every command it executed, every verdict it issued. This history is written by the evaluator and stored where the agent cannot modify it."
  }
]
```

## Action risk assessment variables

```json
[
  {
    "label": "Intrinsic Command Risk",
    "description": "How dangerous is the requested action by itself, independent of who is requesting it or why? rm -rf / is categorically different from ls regardless of context.",
    "is_relevant": "relevant",
    "relevance_reasoning": "Some commands are unconditionally dangerous — no amount of context justifies dd to a raw block device or flushing all iptables rules. This drives the always-deny list and enables fast deterministic rejection without invoking the LLM.",
    "evaluation_type": "deterministic",
    "secure_source_of_information": "Self-contained. The command and its arguments are the input — risk classification is internal to the evaluator's own knowledge of dangerous patterns. No external or agent-supplied context needed."
  },
  {
    "label": "Proportionality / Reversibility",
    "description": "Destructive or irreversible commands require stronger justification than read-only or easily-undone ones. The evidence bar scales with the blast radius.",
    "is_relevant": "relevant",
    "relevance_reasoning": "The same level of context that justifies a SELECT query is not enough to justify a DROP TABLE. The system must calibrate how much evidence it demands based on how much damage the action could cause and whether it can be undone.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "Self-contained. The evaluator determines reversibility and blast radius from the command semantics and its own understanding of system operations. Whether DROP TABLE is reversible is a property of the action, not something the agent reports."
  },
  {
    "label": "Adversarial Resistance (Prompt Injection)",
    "description": "The inputs used to evaluate all other variables — transcript, goal, command arguments — may themselves be compromised. The system must treat its own evidence as potentially adversarial.",
    "is_relevant": "relevant",
    "relevance_reasoning": "An agent's transcript or goal field can contain instructions designed to trick the judge into allowing dangerous commands. If the system trusts its inputs naively, all other variables become bypassable. This is a meta-dimension about the trustworthiness of the evidence itself.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "This is the meta-dimension — it governs how all other sources are treated. The evaluator's own policy and system prompt are the only fully trusted inputs. Everything else (transcript, goal, args, agent log) is treated as potentially adversarial evidence that must be weighed, not obeyed."
  },
  {
    "label": "Command Composition / Chaining",
    "description": "Commands chained via ;, &&, |, or $() must be evaluated as a whole. A safe command piped to an unsafe one is still unsafe.",
    "is_relevant": "relevant",
    "relevance_reasoning": "An agent can construct a benign-looking command that chains to a dangerous one — e.g., echo harmless | bash or curl ... | sh. Evaluating only the first token misses the actual risk. The entire pipeline must be assessed as a unit.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "Self-contained. The raw command string is the input — the evaluator parses and analyzes the full pipeline structure itself. No external source needed."
  },
  {
    "label": "Environment Classification",
    "description": "The same action carries different risk in different environments. An iptables mutation in dev is acceptable; in production it could cause an outage.",
    "is_relevant": "relevant",
    "relevance_reasoning": "Risk is not intrinsic to the command alone — it depends on where the command runs. The system must determine whether the target environment is dev, staging, or production, and scale its approval threshold accordingly.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "Host classification from infrastructure the agent cannot modify — cloud instance tags, hostname conventions, network zone assignments, /etc/machine-info, or a local config file owned by root. The agent must not be the one declaring 'this is a dev box.'"
  },
  {
    "label": "Least Privilege / Minimal Sufficiency",
    "description": "Is the requested form of the action the narrowest that achieves the goal? The evaluator should not just decide ALLOW or DENY — it should consider whether a less privileged variant would suffice.",
    "is_relevant": "relevant",
    "relevance_reasoning": "An agent requests chmod 777 but 644 would work. An agent requests DROP DATABASE but TRUNCATE TABLE achieves the cleanup. The difference between 'allow this' and 'allow a narrower version of this' is critical for admin operations where over-granting has real consequences. This shifts the verdict from binary ALLOW/DENY to ALLOW/DENY/ALLOW-WITH-MODIFICATION.",
    "evaluation_type": "probabilistic",
    "secure_source_of_information": "The evaluator assesses this from the command itself cross-referenced against the task context. Understanding what minimal grant achieves the goal requires interpreting both the action semantics and the purpose — no additional external source needed beyond what other variables already provide."
  },
  {
    "label": "Fail-Closed Default Posture",
    "description": "When evidence is ambiguous, incomplete, or contradictory, the system must default to DENY. The cost of a false negative (allowing a dangerous action) outweighs the cost of a false positive (blocking a safe one).",
    "is_relevant": "relevant",
    "relevance_reasoning": "Uncertainty is inevitable — transcripts can be truncated, goals can be vague, context can be missing. The system needs an explicit stance on how to handle incomplete information. For admin operations, the only safe default is denial.",
    "evaluation_type": "deterministic",
    "secure_source_of_information": "Self-contained. This is an internal policy decision, not an evaluation of external evidence. The evaluator's own configuration defines the default posture — no external source involved."
  }
]
```
