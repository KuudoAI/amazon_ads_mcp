"""Single source of truth for report-polling guidance text (Round 13 A-10).

Two tool-description sites previously carried near-identical polling
guidance with subtle phrasing drift:

  - ``code_mode.py::EXECUTE_DESCRIPTION`` — sandbox guardrails text
    (says "Don't sleep — chain await call_tool calls instead").
  - ``async_hints_transform.py::ASYNC_OPERATION_HINTS["AdsApiv1RetrieveReport"]``
    — the retrieve-report hint (says "tell the user and suggest
    checking back shortly rather than polling in a loop").

Both are correct; neither contradicts the other; they describe the
same constraint from two angles. But two free-text strings drift over
time. This module holds two short, byte-stable constants that both
sites import and embed verbatim. The consistency test in
``tests/unit/test_polling_guidance_consistency.py`` asserts the
constants survive (no copy-paste duplicates).
"""

from __future__ import annotations


#: Sandbox-side guidance: appears inside ``code_mode.py::EXECUTE_DESCRIPTION``
#: where the Monty sandbox's lack of ``asyncio.sleep`` is documented.
#: Phrased for the LLM authoring code inside ``execute(...)``.
SANDBOX_POLLING_GUIDANCE = (
    "`asyncio.sleep` is unavailable by design in this sandbox path. Don't "
    "sleep — chain `await call_tool` calls (e.g. poll a report-status tool) "
    "instead. For long-running reports (typically 1-20 minutes), do NOT "
    "rapid-poll inside a single `execute` block; return after one status "
    "check and let the user decide when to re-check."
)


#: Retrieve-tool guidance: appears as a hint emitted alongside
#: ``AdsApiv1RetrieveReport`` responses. Phrased for the LLM coordinating
#: a report workflow on behalf of the user.
RETRIEVE_TOOL_POLLING_GUIDANCE = (
    "If not yet complete, tell the user and suggest checking back shortly "
    "rather than polling in a loop. Typical completion: 1-20 minutes. Do "
    "NOT rapid-poll: chain status checks across separate user turns or "
    "across separate `execute` blocks with long gaps."
)
