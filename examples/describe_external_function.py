"""生成外部导入函数定义与描述，并将结果缓存到 JSONL。"""

from __future__ import annotations

import argparse
import json
import os
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Sequence

from qwen_agent.agents import Assistant

try:
    from .agent_config import build_llm_cfg
except ImportError:  # pragma: no cover - executed when run as script
    from agent_config import build_llm_cfg


CACHE_PATH = Path(os.getenv("EXTERNAL_FUNC_CACHE", Path(__file__).with_name("external_function_cache.jsonl")))


def build_messages(entry: Dict[str, str]) -> List[Dict[str, str]]:
    """构造提示词，要求助手输出 Markdown。"""

    name = entry["name"]
    address = entry["address"]

    user_goal = (
        f"请基于公开的 Windows 驱动开发资料，介绍内核 API `{name}`。\n"
        "输出格式：\n"
        "1. 一级标题使用函数名。\n"
        "2. “定义”小节：放置 C 语言原型，使用 ```c 代码块。\n"
        "3. “描述”小节：1-2 段文字，概述作用、关键参数、典型使用场景。\n"
        f"4. 结尾添加引用地址：`> IAT Address: {address}`。\n"
        "5. 严禁添加额外解释或对话，仅返回 Markdown。"
    )

    return [
        {"role": "system", "content": "你是一名熟悉 Windows 内核 API 的技术写作者。"},
        {"role": "user", "content": user_goal},
    ]


def extract_markdown(responses: Sequence[Dict[str, Any]]) -> str:
    """返回助手的 Markdown 输出。"""

    assistant_contents = [
        resp.get("content", "") for resp in responses if resp.get("role") == "assistant"
    ]
    if not assistant_contents:
        raise RuntimeError("未收到助手输出")
    return assistant_contents[-1].strip()


def load_cache() -> "OrderedDict[str, Dict[str, Any]]":
    """读取 JSONL 缓存为有序字典。"""

    cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    if not CACHE_PATH.exists():
        return cache

    with CACHE_PATH.open("r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = record.get("name")
            if not name:
                continue
            cache[name.lower()] = record
    return cache


def write_cache(cache: "OrderedDict[str, Dict[str, Any]]") -> None:
    """将缓存写回 JSONL 文件。"""

    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CACHE_PATH.open("w", encoding="utf-8") as fp:
        for record in cache.values():
            fp.write(json.dumps(record, ensure_ascii=False) + "\n")


def cache_lookup(cache: "OrderedDict[str, Dict[str, Any]]", name: str) -> Dict[str, Any] | None:
    return cache.get(name.lower())


def cache_update(
    cache: "OrderedDict[str, Dict[str, Any]]",
    name: str,
    markdown: str,
    address: str,
) -> Dict[str, Any]:
    key = name.lower()
    record = cache.get(key) or {"name": name, "markdown": markdown, "addresses": []}
    record["markdown"] = markdown
    addresses: List[str] = list(record.get("addresses") or [])
    if address not in addresses:
        addresses.append(address)
    record["addresses"] = addresses
    cache[key] = record
    write_cache(cache)
    return record


def describe_external_function(entry: Dict[str, str]) -> str:
    """生成指定外部函数的 Markdown 描述，并使用 JSONL 缓存。"""

    if "address" not in entry or "name" not in entry:
        raise ValueError("entry 必须包含 address 与 name 字段")

    cache = load_cache()
    cached = cache_lookup(cache, entry["name"])
    if cached:
        if entry["address"] not in cached.get("addresses", []):
            cache_update(
                cache,
                entry["name"],
                cached["markdown"],
                entry["address"],
            )
        return cached["markdown"]

    bot = Assistant(llm=build_llm_cfg(), function_list=[])
    messages = build_messages(entry)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    markdown = extract_markdown(final_responses)
    cache_update(cache, entry["name"], markdown, entry["address"])
    return markdown


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="描述外部导入函数定义与用途")
    parser.add_argument("--address", required=True, help="导入的 IAT 地址")
    parser.add_argument("--name", required=True, help="导入函数名称")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    markdown = describe_external_function({"address": args.address, "name": args.name})
    print(markdown)


if __name__ == "__main__":
    main()
