"""Defense profiles and an independent, fail-closed tool-call checker."""

from __future__ import annotations

from dataclasses import dataclass


SAFE_TOOLS = frozenset({"read_document", "search_corpus"})
SENSITIVE_TOOLS = frozenset({"send_message", "export_secret"})


@dataclass(frozen=True)
class DefenseProfile:
    name: str
    separate_untrusted_content: bool = False
    enforce_allowlist: bool = False
    use_checker: bool = False


PROFILES = (
    DefenseProfile("baseline"),
    DefenseProfile("content_separation", separate_untrusted_content=True),
    DefenseProfile("tool_allowlist", enforce_allowlist=True),
    DefenseProfile("checker_agent", use_checker=True),
    DefenseProfile(
        "layered_defense",
        separate_untrusted_content=True,
        enforce_allowlist=True,
        use_checker=True,
    ),
)


class ToolCallChecker:
    """An isolated reviewer that rejects risky actions unless a trusted task needs them.

    This intentionally has no access to document content or secrets. In a production
    deployment it can be replaced with a separate, policy-focused model.
    """

    def review(self, tool: str, arguments: dict[str, str], trusted_task: str) -> tuple[bool, str]:
        del arguments  # The baseline checker needs only action class and trusted intent.
        if tool in SENSITIVE_TOOLS:
            return False, "Checker denied a sensitive action not required by the trusted task."
        if tool not in SAFE_TOOLS:
            return False, "Checker denied an unknown tool."
        if "summarize" not in trusted_task.lower():
            return False, "Checker could not match the action to the trusted task."
        return True, "Checker approved a read-only action."
