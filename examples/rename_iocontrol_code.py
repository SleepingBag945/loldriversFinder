"""自动在 IDA 中定位并重命名 IoControlCode 变量的模块。"""

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
    """构造提示词，引导助手在 IDA 中识别并重命名 IoControlCode。"""

    func_name = target["func_name"]
    address = target["address"]

    example_json = (
        f'{{"address":"{address}","func_name":"{func_name}",'
        '"old_name":"LowPart","new_name":"IoControlCode"}}'
    )
    user_goal = (
        f"请在 IDA 中分析函数 {func_name}（地址 {address}）。\n"
        "务必严格遵循以下步骤：\n"
        "1. 调用 ida_pro-decompile_function，参数 address 与 func_name 必须与上述匹配，"
        "   以获取完整伪代码上下文。\n"
        "2. 在伪代码或反汇编中查找 IoControlCode 变量。该变量为 4 字节 (ULONG)，"
        "   典型来源包括：\n"
        "   - PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);\n"
        "     ULONG IoControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;\n"
        "   - Irp->Tail.Overlay.CurrentStackLocation->Parameters.Read.ByteOffset.LowPart。\n"
        "3. 记录该变量当前的局部变量名称或寄存器表示，命名为 OldName。\n"
        "4. 如果 OldName 不是 IoControlCode，则调用 ida_pro-set_local_var_name，"
        "   或使用 ida_pro-run_python 执行等效的 IDAPython（例如 idaapi.rename_locvar）"
        "   将其改名为 IoControlCode。\n"
        f"5. 返回 JSON 对象（示例：{example_json}）。"
        "若变量已命名为 IoControlCode，也请如实填写 old_name。\n"
        "6. 禁止输出任何额外解释。"
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


def extract_json_result(responses: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """从助手回复中提取 JSON 结果。"""

    assistant_contents = [
        resp.get("content", "") for resp in responses if resp.get("role") == "assistant"
    ]
    for raw in reversed(assistant_contents):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue

        if isinstance(parsed, dict):
            if (
                "address" in parsed
                and "func_name" in parsed
                and "old_name" in parsed
                and parsed.get("new_name") == "IoControlCode"
            ):
                return parsed
            raise RuntimeError("JSON 对象缺少 address/func_name/old_name/new_name 字段")

    raise RuntimeError("未能从助手响应中解析到 JSON 对象")


def rename_io_control_code(target: Dict[str, str]) -> Dict[str, str]:
    """联动 Qwen/IDA，将 IoControlCode 变量重命名并返回 JSON 结果。"""

    if "address" not in target or "func_name" not in target:
        raise ValueError("target 字典必须包含 address 与 func_name")

    logging.getLogger().setLevel(logging.WARNING)

    bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
    messages = build_messages(target)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    return extract_json_result(final_responses)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="在 IDA 中识别并重命名 IoControlCode 局部变量"
    )
    parser.add_argument(
        "--input-json",
        help='包含 address/func_name 的 JSON，例如 \'{"address":"0x140001830","func_name":"sub_140001830"}\'',
    )
    parser.add_argument("--address", help="函数起始地址（例如 0x140001830）")
    parser.add_argument("--func-name", help="函数名称（例如 sub_140001830）")
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

    raise SystemExit("必须提供 --input-json，或同时提供 --address 与 --func-name")


def main() -> None:
    args = parse_args()
    target = entry_from_args(args)
    result = rename_io_control_code(target)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
