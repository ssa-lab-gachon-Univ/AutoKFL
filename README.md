# AutoKFL

A multi-agent-based automated analysis tool for Linux kernel crash **Fault Localization**.  
Composed of 4 agents using LangGraph, it mimics the human analysis process (observation → collection → analysis → evidence synthesis) to estimate bug locations.

## Features

- **Syzkaller Integration**: Fetches crash info and reproducers from [syzkaller.appspot.com](https://syzkaller.appspot.com).
- **Kernel Build & Reproduction**: Clones the Linux kernel, creates worktrees, builds the kernel/image, builds the C reproducer, and reproduces the crash.
- **Fault Localization (FL)**: Uses LLM agents to estimate bug locations and root causes by analyzing the callstack, faulty code, and crash information.

## Architecture

| Agent | Role |
|-------|------|
| **Crash Observer** | Observes the callstack, CPU context, and reproducer, then summarizes the crash point. |
| **Code Collector** | Collects the crash point, related functions/structs, call graphs, and data dependencies. |
| **Code Analyzer** | Detects bug patterns and performs static analysis (memory/bounds, lock order, pointer aliasing, etc.). |
| **Evidence Synthesizer** | Synthesizes evidence, verifies hypothesis consistency, calculates confidence/weights, and draws the final conclusion. |

Routing between agents is done using conditional edges, allowing iterative analysis by returning to previous steps when necessary.

## Requirements

- Python 3.10+
- Dependencies: `pexpect`, `requests`, `langgraph`, `langchain-anthropic`, `langchain-openai`, `langchain-google-genai`, `python-dotenv`, `pydantic`, `libclang`

## Installation

1. Clone the repository and run the following in the project root:

```bash
pip install -e .
```

2. Set API Keys: Create a `.env` file in the project root and set the keys for the LLM you want to use.

```bash
# OpenAI (when using --model gpt)
OPENAI_API_KEY=sk-...

# Anthropic (when using --model claude)
ANTHROPIC_API_KEY=sk-ant-...

# Google (when using --model gemini)
GOOGLE_API_KEY=...
```

## Usage

### CLI Arguments

| Argument | Description |
|----------|-------------|
| `--workdir` | Working directory path (Required) |
| `--task` | Task to execute (Required) |
| `--crash_id` | Syzkaller crash ID or `DUMMY` (Required) |
| `--model` | LLM for FL: `gpt`, `claude`, or `gemini` (Default: `gemini`) |
| `--qemu_ssh` | Use QEMU SSH (Flag) |
| `--run_qemu` | Run QEMU (Flag) |

### Execution by Task

Tasks are usually executed in the following order:

```bash
# 1. Clone Linux kernel (crash_id is not used, any value like DUMMY is fine)
python main.py --workdir ./workdir/ --task clone_linux --crash_id DUMMY

# 2. Check crash info and build kernel (built only if reproducible)
python main.py --workdir ./workdir/ --task build_kernel --crash_id <CRASH_EXTID>

# 3. Build disk image
python main.py --workdir ./workdir/ --task build_image --crash_id DUMMY

# 4. Download C reproducer
python main.py --workdir ./workdir/ --task get_crepro --crash_id <CRASH_EXTID>

# 5. Build C reproducer
python main.py --workdir ./workdir/ --task build_crash --crash_id <CRASH_EXTID>

# 6. Reproduce crash
python main.py --workdir ./workdir/ --task repro_crash --crash_id DUMMY

# 7. Fault Localization (FL) — requires callstack.json, repro.c, and crash_info.json in the workdir
python main.py --workdir ./workdir/ --task fl --crash_id <CRASH_EXTID> --model gemini
# or
python main.py --workdir ./workdir/ --task fl --crash_id <CRASH_EXTID> --model claude
```

### Fault Localization Input Files

When running `--task fl`, the following files must exist in the **workdir**. (The script changes directory to `workdir` during execution and references these paths.)

- `callstack.json` — Parsed callstack
- `repro.c` — C reproducer (or faulty code)
- `crash_info.json` — Syzkaller crash metadata

Example:

```bash
python main.py --workdir ./workdir/ --task fl --crash_id 803e4cb8245b52928347 --model gemini
```

## Project Structure

```
autokfl/
├── main.py                 # CLI entry point
├── setup.py                # Package installation (pip install -e .)
├── agent_design.md         # Agent role, tool, I/O design (if any)
├── autokfl/
│   ├── autokfl.py          # Autokfl class, LangGraph workflow
│   ├── codebase.py         # Codebase / code block data structures
│   ├── util.py             # Utilities for kernel clone/build, repro, etc.
│   ├── qemu.py             # QEMU related functions
│   ├── fault_localizer.py  # Fault localization helper
│   ├── agent/              # 4 agents (crash_observer, code_collector, code_analyzer, evidence_synthesizer)
│   ├── state/              # State definitions like AnalysisState
│   ├── prompt/             # Prompts for each agent
│   └── tool/               # Agent tools (callstack, CFG, taint, confidence, bug patterns, etc.)
```

## TODO
- Implement autokfl with various architectures and compare results
    - Autonomous routing
    - Orchestrator approach
    - Debate/critic
    - Sequential
- Long context handling
- Specialization in race condition fault localization

## License
TBD
