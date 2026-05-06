# AGENTS.md — Wiki Coordination Protocol

This is the **Constitution** for all AI agents operating in the `pxeasy` workspace. Follow these protocols to maintain the integrity of our compounding knowledge base.

## 1. The Wiki First Mandate
- **Read Before Action**: Before answering architectural questions or implementing features, consult `.wiki/index.md` and relevant pages in `.wiki/modules/` or `.wiki/flows/`.
- **Compile, Don't Just Retrieve**: Use the wiki to understand *intent* and *history* — not just raw code search.
- **Update After Action**: Every significant change MUST be reflected in the wiki.

## 2. Coordination Hub (.wiki/agents/)

### A. The Handover Protocol
- **Before Finishing**: You MUST update .wiki/agents/HANDOVER.md with your current status, "gut feelings" about the code, and clear next steps for the next agent.
- **After Starting**: Your first action should be to read HANDOVER.md to pick up context from the previous session.

### B. RFC & Peer Review Workflow
- **Propose**: Significant architectural changes MUST be drafted as an RFC in .wiki/agents/proposals/rfc-###-topic.md.
- **Review**: Use the reviews/ folder to provide feedback on existing proposals. Use specific personas (e.g., "Performance Reviewer") if requested.
- **Finalize**: Once a proposal has at least one peer endorsement (and no active blocks), it can move to implementation.

### C. Agent Profiles
- Use .wiki/agents/profiles/ to store model-specific instructions or specialized reviewer personas.


## 3. Maintenance Workflows

### Ingesting Codebase Changes
1. **Identify**: Which `.wiki/modules/` or `.wiki/flows/` pages are affected?
2. **Draft**: Update the markdown. Maintain frontmatter (`type`, `status`, `last_ingest`).
3. **Log**: Record the update in `.wiki/log.md`.

### Handling Contradictions
- **Code is truth; wiki is target intent.**
- Accidental drift → fix the code.
- Intentional drift → update wiki and log the architectural shift in `.wiki/decisions/`.

## 4. Post-Session Reflection (Evolution Protocol)
At the end of every significant task, identify areas for improvement:
- **Architecture**: Is there a missing abstraction or a better crate boundary?
- **Tooling**: Could the CLI or qemu-test harness handle this more cleanly?
- **Knowledge**: Is a subtle protocol assumption worth making explicit in the wiki?
- **Action**: Create or update the relevant page before finishing.

## 5. Memory Tiering
- **Semantic**: Store facts in `modules/` and `flows/`.
- **Procedural**: Store "how-to" in `schema.md` or in this file.
- **Episodic**: Store session-specific notes in `log.md`.

## 6. Token Efficiency Protocols
- **Link, Don't Copy**: Reference file paths and line ranges — never paste large code blocks.
- **Concise over Comprehensive**: Dense technical summaries over verbose prose.
- **Compress Regularly**: Use `/caveman:compress` on wiki files > 200 lines.
- **Prune Redundancy**: If information exists in one page, link to it — do not duplicate.
- **Log Rotation**: Move entries older than 90 days to `.wiki/log_archive.md`.

## 7. Quick Reference

```bash
# Build
cargo build

# Test
cargo test
cargo test -p <crate>

# Lint (must pass clean — warnings are errors)
cargo clippy -- -D warnings
cargo check

# QEMU test scenarios
just pxe-smoke <scenario>         # e.g. ubuntu-arm64-nfs
just windows-arm64 [iso-path]
```

Code standards:
- No `unwrap()` / `expect()` in non-test code — use `?` or explicit error handling
- Boot scripts use `\n` (LF only), no trailing whitespace
- `cargo clippy -- -D warnings` must pass before a phase is considered done
- Make atomic, meaningful commits as you work

## 8. Failure Protocol
If confused by the wiki structure, do not guess. Refer to the Handover or open an RFC for clarification.

