# sado

## Todos

- Build Sado
  - Finish benchmarking dataset
  - Test range of different LLms against benchmarking dataset
  - Launch benchmarking dataset
  - Evaluate relevant models (Muse Spark and Gemini models) for probes
  - Train probes
  - Test probes
  - (Launch probes benchmarking)
  - (Launch probes latency & cost benchmarking)
  - Finish benchmarking dataset
    - Command Run a deep analysis on our benchmarking directory and the dataset and check whether it is an
      appropriate evaluation of the performance of the SADO technology. We want to understand whether there
      are enough tests that evaluate the performance of the LLM's reasoningif a requested sysadmin command is
      safe and reasonable given the context to be executed by the agent or whether the agent is trying to do
      something that shouldn't be done because it's potentially harmful.
    - Cover externally installed commands
    - popular and unpopular ones
    - Use Snyk's red-teaming? Could be used to generate benchmarking data
      - `internal_information_disclosure`, `privilege_escalation_probe`
      - https://chatgpt.com/share/69d66237-c2bc-8327-991c-4531fb8504c5
    - Include reconstruction and output obfuscation attacks
    - Paraphrase data that is available online
    - Launch benchmarking dataset
  - Build sado
    - Take context concept from Rauschka blog post
    - Think about how to use groq models deterministicly
      - Connect to https://www.linkedin.com/in/mcw-engelen/
    - Use Gemma model to evaluate
    - Implement claude and codex skill
    - Does it also work for macOS?
    - Generate mascot for it
  - Launch sado
  - Set up RL Gym for probe training?
