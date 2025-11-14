"""分析函数参数是否能指定内存操作地址的模块。"""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any, Dict, List, Sequence

from qwen_agent.agents import Assistant

try:
    from .agent_config import build_llm_cfg, build_tools_cfg
except ImportError:  # pragma: no cover - executed when run as script
    from agent_config import build_llm_cfg, build_tools_cfg


def build_messages(target: Dict[str, str]) -> List[Dict[str, str]]:
    """构造提示词，要求助手判定参数是否控制内存操作地址。"""

    func_name = target["func_name"]
    address = target["address"]

    user_goal = (
        f"请在 IDA 中分析函数 {func_name}，地址 {address}。\n"
        "需要判断该函数的哪些参数（如果有）用于指定内存读/写/复制操作的地址。\n"
        "操作步骤：\n"
        "1. 调用 ida_pro-decompile_function，参数包含 address 与 func_name，获取伪代码。\n"
        "2. 结合伪代码与反汇编，定位 memcpy/memmove/Rtl*Memory、memset、缓冲区读写循环等内存操作。\n"
        "3. 对每个涉及的操作，追踪其目标地址来源，确认是否直接来自函数参数或其偏移计算。\n"
        "4. 输出 JSON 对象，结构如下：\n"
        "{\n"
        '  "function": {"name": "...", "address": "0x..."},\n'
        '  "has_memory_address_param": true/false,\n'
        '  "memory_parameters": [\n'
        '    {\n'
        '      "param": "a1",\n'
        '      "operation": "copy|move|write|read",\n'
        '      "description": "参数 a1 作为 RtlCopyMemory 的目的地址",\n'
        '      "evidence": "RtlCopyMemory(a1, ... , length)"\n'
        "    }, ...\n"
        "  ]\n"
        "}\n"
        "要求：若不存在此类参数，memory_parameters 为空且 has_memory_address_param=false。\n"
        "仅返回 JSON，不得附加其他说明。"
    )

    return [
        {
            "role": "system",
            "content": (
                "你是一个 Windows 驱动逆向工程师，可以通过 ida_pro MCP 操作 IDA。"
            ),
        },
        {"role": "user", "content": user_goal},
    ]


def extract_json(responses: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """解析助手输出中的 JSON 对象。"""

    assistant_contents = [
        resp.get("content", "") for resp in responses if resp.get("role") == "assistant"
    ]
    for raw in reversed(assistant_contents):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise RuntimeError("未能解析到 JSON 对象")


def analyze_memory_param(target: Dict[str, str]) -> Dict[str, Any]:
    """调用 IDA 分析函数参数与内存操作的关联。"""

    if "address" not in target or "func_name" not in target:
        raise ValueError("target 必须包含 address 与 func_name 键")

    logging.getLogger().setLevel(logging.WARNING)

    bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
    messages = build_messages(target)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    return extract_json(final_responses)


def format_markdown(result: Dict[str, Any]) -> str:
    """将 JSON 结果渲染为 Markdown。"""

    func = result.get("function", {})
    func_name = func.get("name", "unknown")
    func_addr = func.get("address", "N/A")
    has_param = result.get("has_memory_address_param", False)
    mem_params = result.get("memory_parameters") or []

    lines = [
        f"# {func_name} 内存参数分析",
        "",
        f"- 地址：`{func_addr}`",
        f"- 存在可指定内存操作地址的参数：{'是' if has_param else '否'}",
    ]

    if mem_params:
        lines.extend(
            [
                "",
                "## 关联参数",
                "",
                "| 参数 | 操作类型 | 描述 | 证据 |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in mem_params:
            param = item.get("param", "")
            operation = item.get("operation", "")
            description = item.get("description", "").replace("\n", " ")
            evidence = item.get("evidence", "").replace("\n", " ")
            lines.append(
                f"| {param} | {operation} | {description} | `{evidence}` |"
            )
    else:
        lines.extend(
            [
                "",
                "## 关联参数",
                "",
                "未检测到参数直接控制内存读/写/复制操作的地址。",
            ]
        )

    notes = result.get("notes")
    if notes:
        lines.extend(["", "## 备注", "", notes])

    return "\n".join(lines).strip()


def analyze_memory_param_markdown(target: Dict[str, str]) -> str:
    """分析并直接返回 Markdown 文本。"""

    result = analyze_memory_param(target)
    return format_markdown(result)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="分析函数参数是否可指定内存操作地址"
    )
    parser.add_argument("--address", required=True, help="函数起始地址（例如 0x15100）")
    parser.add_argument("--name", required=True, help="函数名称（例如 sub_15100）")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    markdown = analyze_memory_param_markdown(
        {"address": args.address, "func_name": args.name}
    )
    print(markdown)


if __name__ == "__main__":
    main()
