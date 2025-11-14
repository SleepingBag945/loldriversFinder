"""解析 DriverObject->MajorFunction[14] 目标的辅助模块。"""

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
    """构造提示词，指导助手调用 decompile_function 并返回 JSON。"""

    func_name = target["func_name"]
    address = target["address"]

    user_goal = (
        f"请在 IDA 中分析函数 {func_name}，地址 {address}。\n"
        "必须严格按照以下步骤操作：\n"
        "1. 调用 ida_pro-decompile_function，参数 address 与 func_name 均匹配上述函数。\n"
        "2. 在伪代码中找到对 IoCreateDevice 的调用，审查其第一个参数 DriverObject。\n"
        "3. 分析 IoCreateDevice 调用前对 DriverObject->MajorFunction[14] 的赋值，确定它指向的处理函数地址与名称。\n"
        "4. 仅返回 JSON 对象，例如 {\"address\":\"0x140001830\",\"func_name\":\"sub_140001830\"}。禁止附加解释。"
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


def extract_json_object(responses: Sequence[Dict[str, Any]]) -> Dict[str, str]:
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
            if "address" in parsed and "func_name" in parsed:
                return parsed
            raise RuntimeError("JSON 对象缺少 address 或 func_name 字段")

    raise RuntimeError("未能从助手响应中解析到 JSON 对象")


def analyze_major_function_target(target: Dict[str, str]) -> Dict[str, str]:
    """对指定函数进行分析并返回 MajorFunction[14] 目标。"""

    if "address" not in target or "func_name" not in target:
        raise ValueError("target 字典必须包含 address 与 func_name 键")

    logging.getLogger().setLevel(logging.WARNING)

    bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
    messages = build_messages(target)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    return extract_json_object(final_responses)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="分析 DriverObject->MajorFunction[14] 指向的函数"
    )
    parser.add_argument(
        "--input-json",
        help='包含 address 与 func_name 的 JSON 字符串，例如 \'{"address":"0x11170","func_name":"sub_11170"}\'',
    )
    parser.add_argument("--address", help="目标函数的起始地址（例如 0x11170）")
    parser.add_argument("--func-name", help="目标函数名称（例如 sub_11170）")
    return parser.parse_args()


def entry_from_args(args: argparse.Namespace) -> Dict[str, str]:
    if args.input_json:
        try:
            data = json.loads(args.input_json)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"无法解析 --input-json：{exc}") from exc
        return data

    if args.address and args.func_name:
        return {"address": args.address, "func_name": args.func_name}

    raise SystemExit("必须提供 --input-json 或同时提供 --address 与 --func-name")


def main() -> None:
    args = parse_args()
    target = entry_from_args(args)
    result = analyze_major_function_target(target)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()

