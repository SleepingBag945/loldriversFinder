"""生成内部函数的 Markdown 定义与描述（通过 IDA 反编译）。"""

from __future__ import annotations

import argparse
import logging
from typing import Any, Dict, List, Sequence

from qwen_agent.agents import Assistant

try:
    from .agent_config import build_llm_cfg, build_tools_cfg
except ImportError:  # pragma: no cover - executed when run as script
    from agent_config import build_llm_cfg, build_tools_cfg


def build_messages(entry: Dict[str, str]) -> List[Dict[str, str]]:
    """构造提示词，要求助手调用 IDA 并输出 Markdown。"""

    name = entry["name"]
    address = entry["address"]

    user_goal = (
        f"请在 IDA 中分析内部函数 {name}，其起始地址为 {address}。\n"
        "必须严格按照以下步骤：\n"
        "1. 调用 ida_pro-decompile_function，参数应包含 address 与 func_name，获取该函数伪代码。\n"
        "2. 根据伪代码总结函数功能、关键参数/返回值、重要分支或调用。\n"
        "3. 输出 Markdown：\n"
        "   * 一级标题为函数名。\n"
        "   * “定义”小节：给出最合理的 C 风格函数签名，使用 ```c 代码块。\n"
        "   * “描述”小节：1-2 段文字概述函数整体逻辑，可提及重要调用或副作用。\n"
        "   * 如果分析表明该函数包含内存复制/移动操作（例如 memcpy、memmove、RtlCopyMemory 等），\n"
        "     请在描述末尾追加 `# MEM #` 用于标记。\n"
        f"4. 在结尾添加 `> Address: {address}`。\n"
        "5. 只输出 Markdown，不要包含额外解释或对话。"
    )

    return [
        {
            "role": "system",
            "content": (
                "你是一个 Windows 驱动逆向工程师，你可以通过 ida_pro MCP 操作 IDA。"
            ),
        },
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


def describe_internal_function(entry: Dict[str, str]) -> str:
    """调用 IDA 反编译并生成 Markdown 描述。"""

    if "address" not in entry or "name" not in entry:
        raise ValueError("entry 必须包含 address 与 name 字段")

    logging.getLogger().setLevel(logging.WARNING)

    bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
    messages = build_messages(entry)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    return extract_markdown(final_responses)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="描述内部函数的定义与用途")
    parser.add_argument("--address", required=True, help="函数起始地址")
    parser.add_argument("--name", required=True, help="函数名称")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    markdown = describe_internal_function({"address": args.address, "name": args.name})
    print(markdown)


if __name__ == "__main__":
    main()
