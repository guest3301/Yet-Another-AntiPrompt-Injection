from guard.models import Provenance, TrustLevel

SOURCE_TRUST_MAP = {
    "system_prompt": TrustLevel.SYSTEM,
    "developer_msg": TrustLevel.SYSTEM,
    "user_chat": TrustLevel.USER,
    "user_upload": TrustLevel.USER,
    "rag_chunk": TrustLevel.RETRIEVAL,
    "web_scrape": TrustLevel.RETRIEVAL,
    "tool_result": TrustLevel.TOOL_OUTPUT,
    "agent_message": TrustLevel.INTER_AGENT,
}


def tag_content(source, origin_id="", transform_chain=None):
    trust = SOURCE_TRUST_MAP.get(source, TrustLevel.RETRIEVAL)
    return Provenance(
        source=source,
        trust_level=trust,
        origin_id=origin_id,
        transform_chain=transform_chain or [],
    )


def is_untrusted(prov):
    return prov.trust_level in {
        TrustLevel.RETRIEVAL,
        TrustLevel.TOOL_OUTPUT,
        TrustLevel.INTER_AGENT,
    }
