"""列出给定函数所有子函数（直接调用）的模块。"""

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
    """构造提示词，指导助手列出所有直接调用的子函数。"""

    func_name = target["func_name"]
    address = target["address"]

    user_goal = (
        f"请在 IDA 中分析函数 {func_name}，地址 {address}。\n"
        "1. 使用 ida_pro-decompile_function 获取伪代码，并结合反汇编识别所有直接调用的子函数。\n"
        "2. 对每个调用，确定其目标函数地址与名称；若是导入 API，则使用导入名称并把地址写成 IAT 项地址。\n"
        "3. 按地址排序并去重，返回 JSON 数组，元素形如 "
        '{"address":"0x140001B80","name":"sub_140001B80","type":"internal"}。\n'
        "   * type=internal 表示当前二进制内的子函数；type=external 表示导入函数/外部符号。\n"
        "4. 仅输出 JSON，不要附加任何解释。"
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


def extract_json_array(responses: Sequence[Dict[str, Any]]) -> List[Dict[str, str]]:
    """解析助手输出中的 JSON 数组。"""

    assistant_contents = [
        resp.get("content", "") for resp in responses if resp.get("role") == "assistant"
    ]
    for raw in reversed(assistant_contents):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue

        if isinstance(parsed, list):
            return parsed

    raise RuntimeError("未能从助手响应中解析到 JSON 数组")


def list_subfunctions(target: Dict[str, str]) -> List[Dict[str, str]]:
    """列出指定函数的所有直接调用子函数。"""

    if "address" not in target or "func_name" not in target:
        raise ValueError("target 字典必须包含 address 与 func_name 键")

    logging.getLogger().setLevel(logging.WARNING)

    bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
    messages = build_messages(target)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    return extract_json_array(final_responses)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="列出函数的子函数列表")
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
    result = list_subfunctions(target)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

