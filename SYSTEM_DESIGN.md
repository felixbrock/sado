# Assumptions

- The solution only has to work for Claude Code

# System components

## Authority component

- Operator - to execute commands
- Judge - decision making engine with probabilistic and deterministic components whether command should be executed
  - Rules - to make deterministic decisions
  - Decision making model - defining the foundation of decision making
  - Decision variables - the dimensions to analyze for making decisions

## The requesting agent

tbd - what must be true about the requesting agent?

# Design decisions

- Context is the only basis for authorization — there is no pre-established trust, no identity system, no credential; the decision is made from the evidence available at request time
- The system must fail closed — when the system doesn't know what to do, it must deny
- Every request must be evaluated independently against current evidence — cached grants and pre-authorized scopes are unsafe because context validity decays over time
