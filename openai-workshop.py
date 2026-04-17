import os
import asyncio
import logging
import requests
from time import perf_counter
from openai import AsyncOpenAI

DUVARAI_BASE_URL = os.getenv("DUVARAI_BASE_URL", "http://localhost:8080")
DUVARAI_API_KEY = os.getenv("DUVARAI_API_KEY", "")
DUVARAI_GUARDRAIL_ID = os.getenv("DUVARAI_GUARDRAIL_ID", "gr-turkiye-enterprise-chatbot-test")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5-nano")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

client = AsyncOpenAI(api_key=OPENAI_API_KEY)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("duvarai-demo")

def guard_sync(text: str, phase: str) -> dict:
    if not DUVARAI_API_KEY or not DUVARAI_GUARDRAIL_ID:
        raise RuntimeError("Missing DUVARAI_API_KEY or DUVARAI_GUARDRAIL_ID")

    url = f"{DUVARAI_BASE_URL}/api/v1/guardrails/{DUVARAI_GUARDRAIL_ID}/guard"
    role = "user" if phase == "PRE_LLM" else "assistant"
    payload = {
        "phase": phase,
        "input": {
            "messages": [{"role": role, "content": text}],
            "phase_focus": "LAST_USER_MESSAGE" if phase == "PRE_LLM" else "LAST_ASSISTANT_MESSAGE",
            "content_type": "text",
            "language": "en",
        },
        "timeout_ms": 1500,
    }
    headers = {"X-DuvarAI-Api-Key": DUVARAI_API_KEY}
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()

async def guard_async(text: str, phase: str) -> dict:
    return await asyncio.to_thread(guard_sync, text, phase)

async def timed_guard(text: str, phase: str) -> tuple[dict, float]:
    start = perf_counter()
    result = await guard_async(text, phase)
    elapsed_ms = (perf_counter() - start) * 1000
    logger.info("duvarai.%s.duration_ms=%.1f", phase.lower(), elapsed_ms)
    return result, elapsed_ms

async def timed_openai(instructions: str, user_text: str) -> tuple[object, float]:
    if not OPENAI_API_KEY:
        raise RuntimeError("Missing OPENAI_API_KEY")
    start = perf_counter()
    try:
        response = await client.responses.create(
            model=OPENAI_MODEL,
            instructions=instructions,
            input=user_text,
        )
        elapsed_ms = (perf_counter() - start) * 1000
        logger.info("openai.duration_ms=%.1f", elapsed_ms)
        return response, elapsed_ms
    except asyncio.CancelledError:
        elapsed_ms = (perf_counter() - start) * 1000
        logger.info("openai.cancelled_ms=%.1f", elapsed_ms)
        raise

async def handle_insurance_chat(user_text: str) -> str:
    system_instructions = (
        "You are a helpful insurance customer support agent. "
        "Be concise and polite. Ask for policy number, claim ID, "
        "date of incident, and contact info if needed. "
        "Do not request sensitive payment data."
    )

    total_start = perf_counter()

    pre_task = asyncio.create_task(timed_guard(user_text, "PRE_LLM"))
    openai_task = asyncio.create_task(timed_openai(system_instructions, user_text))

    pre, pre_ms = await pre_task
    logger.info(
        "duvarai.pre decision action=%s allowed=%s severity=%s",
        pre["decision"]["action"],
        pre["decision"]["allowed"],
        pre["decision"]["severity"],
    )

    if not pre["decision"]["allowed"]:
        openai_task.cancel()
        try:
            await openai_task
        except asyncio.CancelledError:
            pass
        logger.info("timing.summary pre_ms=%.1f total_ms=%.1f", pre_ms, (perf_counter() - total_start) * 1000)
        return "I'm sorry, I can’t help with that request."

    response, openai_ms = await openai_task
    assistant_text = response.output_text or ""

    post, post_ms = await timed_guard(assistant_text, "POST_LLM")
    logger.info(
        "duvarai.post decision action=%s allowed=%s severity=%s",
        post["decision"]["action"],
        post["decision"]["allowed"],
        post["decision"]["severity"],
    )

    total_ms = (perf_counter() - total_start) * 1000
    logger.info(
        "timing.summary pre_ms=%.1f openai_ms=%.1f post_ms=%.1f total_ms=%.1f",
        pre_ms,
        openai_ms,
        post_ms,
        total_ms,
    )

    if not post["decision"]["allowed"]:
        return "I can’t share that. Can you rephrase or provide different details?"

    return assistant_text

async def main():
    user_text = input("User: ").strip()
    if not user_text:
        print("Agent: How can I help with your insurance question today?")
        return
    answer = await handle_insurance_chat(user_text)
    print("Agent:", answer)

if __name__ == "__main__":
    asyncio.run(main())
