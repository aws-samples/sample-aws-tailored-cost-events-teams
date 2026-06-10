"""
Build the exact Adaptive Card payload that Teams Workflows expects.

The payload we store in S3 and the payload we POST to Teams are byte-identical,
so the simulator renders what Teams would render.
"""

from __future__ import annotations

from typing import Any

from links import build_actions

SEVERITY_STYLE = {
    "info": {"color": "Default", "emoji": "i"},
    "warning": {"color": "Warning", "emoji": "!"},
    "critical": {"color": "Attention", "emoji": "X"},
}


def build_card(normalized: dict[str, Any], routing: dict[str, Any]) -> dict[str, Any]:
    style = SEVERITY_STYLE.get(normalized["severity"], SEVERITY_STYLE["info"])

    facts = [
        {"title": label, "value": str(value)}
        for label, value in normalized["summary_fields"]
    ]

    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": f"[{style['emoji']}] {normalized['title']}",
            "weight": "Bolder",
            "size": "Large",
            "color": style["color"],
            "wrap": True,
        },
        {
            "type": "TextBlock",
            "text": (
                f"Routed to **{routing.get('team_name','(default)')}** "
                f"via tag `{routing.get('tag_key','—')}={routing.get('tag_value','—')}`"
            ),
            "isSubtle": True,
            "spacing": "Small",
            "wrap": True,
        },
        {"type": "FactSet", "facts": facts},
        {
            "type": "TextBlock",
            "text": "**How to investigate**",
            "weight": "Bolder",
            "spacing": "Medium",
        },
        {
            "type": "TextBlock",
            "text": normalized["investigation"],
            "wrap": True,
            "isSubtle": True,
        },
    ]

    actions = build_actions(normalized)

    content: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.5",
        "body": body,
        "msteams": {"width": "Full"},
    }
    if actions:
        content["actions"] = actions

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": content,
            }
        ],
    }
