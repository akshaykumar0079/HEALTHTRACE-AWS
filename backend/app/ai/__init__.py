"""AI incident intelligence (Phase 1).

Everything here is additive and off by default. The deterministic path in
``templates`` always works with no model; a local model (Ollama) is optional and
its output is only ever shown after ``validate`` has checked every claim against
a sanitised evidence bundle. See docs/ai-incident-intelligence.md.
"""
