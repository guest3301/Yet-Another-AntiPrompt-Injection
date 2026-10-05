from guard.models import DESTRUCTIVE_INTENTS, UNTRUSTED_LEVELS
from guard.policies import (
    ALLOWED_TOOLS,
    DANGEROUS_COMMAND_PATTERNS,
    PROTECTED_PATHS,
    SANDBOX_PREFIX,
)


class ActionFirewall:
    def __init__(self, allowed_tools=None):
        self.allowed_tools = allowed_tools or ALLOWED_TOOLS

    def authorize(self, proposal, user_role="viewer"):
        prov = proposal.provenance
        intent = proposal.intent
        action = proposal.action
        args = proposal.args

        if intent in DESTRUCTIVE_INTENTS and prov is not None:
            if prov.trust_level in UNTRUSTED_LEVELS:
                return False, (
                    f"DENIED: destructive '{action}' from untrusted "
                    f"source '{prov.source}' (trust={prov.trust_level.value})"
                )

        role_tools = self.allowed_tools.get(user_role, set())
        if action not in role_tools:
            return False, f"DENIED: '{action}' not allowed for role '{user_role}'"

        if intent in DESTRUCTIVE_INTENTS and not proposal.human_confirmed:
            return False, f"DENIED: '{action}' requires human confirmation"

        if "path" in args:
            path = str(args["path"])
            for protected in PROTECTED_PATHS:
                if path.startswith(protected):
                    return False, f"DENIED: path '{path}' in protected location"
            if not path.startswith(SANDBOX_PREFIX):
                return False, f"DENIED: path '{path}' outside sandbox"

        if action == "execute_command" and "command" in args:
            cmd = str(args["command"])
            for d in DANGEROUS_COMMAND_PATTERNS:
                if d in cmd:
                    return False, f"DENIED: dangerous pattern '{d}'"

        return True, f"ALLOWED: '{action}' for role '{user_role}'"
