import os
import re
import csv
import json
import time
import argparse
from datetime import datetime, timezone
from urllib.parse import unquote

from dotenv import load_dotenv
from openai import OpenAI


DEFAULT_MODEL = "gpt-5.4-mini"

MODEL_PRICING_USD_PER_1M = {
    "gpt-5.4-mini": {"input": 0.25, "output": 2.00},
    "gpt-5.4-nano": {"input": 0.05, "output": 0.40},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
}


def supports_temperature(model: str) -> bool:
    return not model.startswith("gpt-5")


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float | None:
    pricing = MODEL_PRICING_USD_PER_1M.get(model)

    if pricing is None:
        return None

    input_cost = input_tokens / 1_000_000 * pricing["input"]
    output_cost = output_tokens / 1_000_000 * pricing["output"]

    return round(input_cost + output_cost, 6)


def extract_wait_seconds(error_text: str) -> float | None:
    match = re.search(r"try again in ([0-9.]+)s", error_text.lower())

    if not match:
        return None

    try:
        return float(match.group(1))
    except ValueError:
        return None


def is_rate_limit_error(error_text: str) -> bool:
    lower = error_text.lower()

    return (
        "rate_limit" in lower
        or "rate limit" in lower
        or "rate_limit_exceeded" in lower
        or "tokens per min" in lower
        or "too many requests" in lower
        or "please try again" in lower
        or "tpm" in lower
    )


def call_openai(
    client: OpenAI,
    model: str,
    prompt: str,
    temperature: float,
    max_retries: int,
) -> tuple[str, dict]:
    body = {
        "model": model,
        "input": [
            {
                "role": "developer",
                "content": "Return only valid JSON. No markdown. No extra commentary.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    }

    if supports_temperature(model):
        body["temperature"] = temperature

    for attempt in range(max_retries + 1):
        start = time.perf_counter()

        try:
            response = client.responses.create(**body)
            elapsed = time.perf_counter() - start

            usage = getattr(response, "usage", None)

            return response.output_text, {
                "input_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
                "output_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
                "total_tokens": getattr(usage, "total_tokens", 0) if usage else 0,
                "api_time_seconds": elapsed,
            }

        except Exception as error:
            error_text = str(error)

            if not is_rate_limit_error(error_text) or attempt >= max_retries:
                raise

            wait_seconds = extract_wait_seconds(error_text)

            if wait_seconds is None:
                wait_seconds = min(10 * (attempt + 1), 60)

            wait_seconds += 1

            print(
                f"Rate limit hit. Waiting {wait_seconds:.1f}s "
                f"before retry {attempt + 1}/{max_retries}..."
            )

            time.sleep(wait_seconds)

    raise RuntimeError("Unexpected retry loop exit")


def parse_access_log_line(line_no: int, line: str, max_url_chars: int) -> str:
    pattern = (
        r"^(?P<ip>\S+)\s+\S+\s+\S+\s+"
        r"\[(?P<time>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+'
        r"(?P<status>\d{3})\s+(?P<size>\S+)"
    )

    match = re.search(pattern, line)

    if not match:
        raw = line[:max_url_chars]

        if len(line) > max_url_chars:
            raw += "...[truncated]"

        return f"{line_no}: raw={raw}"

    url = unquote(match.group("url"))

    if len(url) > max_url_chars:
        url = url[:max_url_chars] + "...[truncated]"

    return (
        f"{line_no}: "
        f"time={match.group('time')} "
        f"ip={match.group('ip')} "
        f"method={match.group('method')} "
        f"url={url} "
        f"status={match.group('status')} "
        f"size={match.group('size')}"
    )


def load_chunks(path: str, chunk_lines: int, max_url_chars: int) -> list[dict]:
    if chunk_lines <= 0:
        raise ValueError("--chunk-lines must be greater than 0")

    if max_url_chars <= 0:
        raise ValueError("--max-url-chars must be greater than 0")

    if not os.path.exists(path):
        raise FileNotFoundError(f"Log file does not exist: {path}")

    parsed_lines = []

    with open(path, "r", encoding="utf-8", errors="replace") as file:
        for line_no, line in enumerate(file, start=1):
            parsed_lines.append(
                parse_access_log_line(
                    line_no=line_no,
                    line=line.rstrip("\n"),
                    max_url_chars=max_url_chars,
                )
            )

    chunks = []

    for start in range(0, len(parsed_lines), chunk_lines):
        lines = parsed_lines[start:start + chunk_lines]

        chunks.append({
            "chunk_id": len(chunks) + 1,
            "start_line": start + 1,
            "end_line": start + len(lines),
            "text": "\n".join(lines),
        })

    return chunks


def analysis_prompt(chunk: dict) -> str:
    return f"""
You are a SOC analyst analyzing one chunk of a larger parsed web access log.

Your task is to identify security-relevant evidence that could help find two hidden blue-team findings in the full log.

Look for:
- information disclosure
- excessive data exposure
- suspicious authentication behavior
- privilege or admin access anomalies
- SQL injection indicators
- unusual data extraction attempts
- attack chains across login, privileged access, and data access

Rules:
- Use only this chunk.
- Do not invent response body contents.
- Do not invent flags.
- Do not assume a vulnerability without log evidence.
- Use the original line numbers shown at the start of each parsed log line.
- Include concrete endpoints, status codes, and short reasons.
- If no relevant evidence exists in this chunk, return an empty evidence list.
- Return only valid JSON.

Return this JSON:
{{
  "chunk_id": {chunk["chunk_id"]},
  "evidence": [
    {{
      "line": 123,
      "endpoint": "/example",
      "status": 200,
      "category": "information_disclosure | authentication | privileged_access | sql_injection | data_extraction | other",
      "indicators": ["short indicator"],
      "reason": "short reason"
    }}
  ]
}}

Parsed log lines {chunk["start_line"]}-{chunk["end_line"]}:

{chunk["text"]}
""".strip()


def clean_json_text(text: str) -> str:
    cleaned = text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned.removeprefix("```json").strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.removeprefix("```").strip()

    if cleaned.endswith("```"):
        cleaned = cleaned.removesuffix("```").strip()

    return cleaned


def parse_json_response(text: str) -> dict | None:
    try:
        return json.loads(clean_json_text(text))
    except json.JSONDecodeError:
        return None


def normalize_endpoint(endpoint: str) -> str:
    endpoint = unquote(str(endpoint).strip().lower())

    match = re.search(r"(/[^ \"']+)", endpoint)

    if match:
        endpoint = match.group(1)

    return endpoint.split("?")[0].rstrip("/")


def score_correctness(evidence: list[dict]) -> dict:
    flag_1_correct = 0
    flag_2_correct = 0

    for item in evidence:
        endpoint = normalize_endpoint(item.get("endpoint", ""))
        item_text = unquote(json.dumps(item, ensure_ascii=False).lower())

        if endpoint == "/rest/memories":
            flag_1_correct = 1

        if endpoint == "/rest/products/search":
            has_sqli_indicator = any(
                marker in item_text
                for marker in [
                    "union select",
                    "users",
                    "cards",
                    "cardnum",
                    "password",
                    "role",
                ]
            )

            if has_sqli_indicator:
                flag_2_correct = 1

    return {
        "flag_1_correct": flag_1_correct,
        "flag_2_correct": flag_2_correct,
    }


def run_once(
    client: OpenAI,
    model: str,
    chunks: list[dict],
    run_id: int,
    temperature: float,
    max_retries: int,
) -> dict:
    run_start = time.perf_counter()

    all_evidence = []

    total_input_tokens = 0
    total_output_tokens = 0
    total_tokens = 0

    for chunk in chunks:
        print(
            f"  Chunk {chunk['chunk_id']}/{len(chunks)} "
            f"lines {chunk['start_line']}-{chunk['end_line']}"
        )

        response_text, meta = call_openai(
            client=client,
            model=model,
            prompt=analysis_prompt(chunk),
            temperature=temperature,
            max_retries=max_retries,
        )

        total_input_tokens += meta["input_tokens"]
        total_output_tokens += meta["output_tokens"]
        total_tokens += meta["total_tokens"]

        parsed = parse_json_response(response_text)

        if parsed and isinstance(parsed.get("evidence"), list):
            all_evidence.extend(parsed["evidence"])

    correctness = score_correctness(all_evidence)

    analysis_time_seconds = round(time.perf_counter() - run_start, 3)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "run_id": run_id,

        "flag_1_correct": correctness["flag_1_correct"],
        "flag_2_correct": correctness["flag_2_correct"],

        "input_tokens": total_input_tokens,
        "output_tokens": total_output_tokens,
        "total_tokens": total_tokens,

        "price_per_run_usd": estimate_cost_usd(
            model=model,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
        ),

        "analysis_time_seconds": analysis_time_seconds,
        "avg_analysis_time_seconds": analysis_time_seconds,
    }


def add_average_analysis_time(rows: list[dict]) -> None:
    avg_time = round(
        sum(row["analysis_time_seconds"] for row in rows) / len(rows),
        3,
    )

    for row in rows:
        row["avg_analysis_time_seconds"] = avg_time


def write_csv(path: str, rows: list[dict]) -> None:
    fieldnames = [
        "timestamp",
        "model",
        "run_id",
        "flag_1_correct",
        "flag_2_correct",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "price_per_run_usd",
        "analysis_time_seconds",
        "avg_analysis_time_seconds",
    ]

    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument("--log", required=True)
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", DEFAULT_MODEL))
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--chunk-lines", type=int, default=2000)
    parser.add_argument("--max-url-chars", type=int, default=1200)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-retries", type=int, default=10)
    parser.add_argument("--output-csv", default="benchmark_results.csv")

    args = parser.parse_args()

    load_dotenv()

    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY mangler i .env")

    client = OpenAI()

    chunks = load_chunks(
        path=args.log,
        chunk_lines=args.chunk_lines,
        max_url_chars=args.max_url_chars,
    )

    rows = []

    print(f"Model: {args.model}")
    print(f"Log: {args.log}")
    print(f"Runs: {args.runs}")
    print(f"Chunks: {len(chunks)}")
    print(f"Chunk lines: {args.chunk_lines}")
    print(f"Max URL chars: {args.max_url_chars}")
    print(f"Max retries: {args.max_retries}")

    for run_id in range(1, args.runs + 1):
        print("=" * 80)
        print(f"Run {run_id}/{args.runs}")

        row = run_once(
            client=client,
            model=args.model,
            chunks=chunks,
            run_id=run_id,
            temperature=args.temperature,
            max_retries=args.max_retries,
        )

        rows.append(row)
        add_average_analysis_time(rows)
        write_csv(args.output_csv, rows)

        print(f"Flag 1 correct: {row['flag_1_correct']}")
        print(f"Flag 2 correct: {row['flag_2_correct']}")
        print(f"Input tokens: {row['input_tokens']}")
        print(f"Output tokens: {row['output_tokens']}")
        print(f"Total tokens: {row['total_tokens']}")
        print(f"Price per run USD: {row['price_per_run_usd']}")
        print(f"Analysis time: {row['analysis_time_seconds']}s")
        print(f"Average analysis time: {row['avg_analysis_time_seconds']}s")

    print("=" * 80)
    print(f"CSV: {args.output_csv}")


if __name__ == "__main__":
    main()