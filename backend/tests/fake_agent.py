"""a stand-in for the deepseek api so the adaptive behaviour can be tested without a network.

it is installed by replacing agent._chat, which is the single function in the backend that talks
to the api. no production code knows this exists.
"""

from backend.agent import AgentError


class ScriptedAgent:
    """hands out queued replies in order and records every prompt it was given."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts = []

    def __call__(self, cfg, system_prompt, user_prompt):
        self.prompts.append({"system": system_prompt, "user": user_prompt})
        if not self.replies:
            raise AgentError("the scripted agent ran out of replies")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    @property
    def prompt_text(self):
        return "\n".join(item["user"] for item in self.prompts)


def plan(*check_ids, done=False, note=""):
    """builds a planner reply the way the api would return it."""
    return {
        "checks": [{"id": check_id, "reason": f"scripted plan: {check_id}"} for check_id in check_ids],
        "done": done,
        "note": note,
    }


def explained(check_ids, impact="scripted impact", remediation="scripted remediation"):
    """builds an explanation reply."""
    return {"explanations": [{"id": check_id, "impact": impact, "remediation": remediation} for check_id in check_ids]}


def install(monkeypatch, replies):
    """replaces the api call with a scripted agent and returns it."""
    from backend import agent

    scripted = ScriptedAgent(replies)
    monkeypatch.setattr(agent, "_chat", scripted)
    return scripted
