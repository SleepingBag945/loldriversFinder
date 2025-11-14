"""在 IDA 中为 func2 设置 DriverDispatch 原型。"""

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


TARGET_PROTOTYPE = (
    "NTSTATUS DriverDispatch(_DEVICE_OBJECT *DeviceObject, _IRP *Irp);"
)


def build_messages(target: Dict[str, str]) -> List[Dict[str, str]]:
    """构造提示词，要求助手设置 DriverDispatch 原型。"""

    func_name = target["func_name"]
    address = target["address"]

    user_goal = (
        f"请在 IDA 中处理函数 {func_name}（地址 {address}），并完成以下要求：\n"
        "1. 调用 ida_pro-decompile_function，address 与 func_name 必须与上述一致，"
        "   获取完整伪代码以确认上下文；\n"
        "2. 确认函数中 IoControlCode 局部变量已经重命名为准确的标识符；"
        "   如未命名为 IoControlCode，请返回失败信息；\n"
        "3. 调用 ida_pro-set_function_prototype，将该函数的原型修改为：\n"
        f"   `{TARGET_PROTOTYPE}`\n"
        "4. 返回 JSON："
        '{"address":"%s","func_name":"%s","prototype":"%s","status":"ok"}`；'
        "若步骤失败，请返回包含 `status` 字段的 JSON 并说明原因；\n"
        "5. 禁止添加额外解释或 Markdown，仅返回 JSON。" % (address, func_name, TARGET_PROTOTYPE)
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


def extract_json_result(responses: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """解析助手最终 JSON 输出。"""

    assistant_contents = [
        resp.get("content", "") for resp in responses if resp.get("role") == "assistant"
    ]
    for raw in reversed(assistant_contents):
        raw = raw.strip()
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    raise RuntimeError("未从助手响应中获取到 JSON 结果")


def define_driver_dispatch(target: Dict[str, str]) -> Dict[str, Any]:
    """调用 IDA 设置 DriverDispatch 原型。"""

    if "address" not in target or "func_name" not in target:
        raise ValueError("target 必须包含 address 与 func_name 键")

    logging.getLogger().setLevel(logging.WARNING)

    bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
    messages = build_messages(target)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    return extract_json_result(final_responses)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="设置函数原型为 DriverDispatch(DeviceObject, Irp)"
    )
    parser.add_argument("--address", required=True, help="函数地址，例如 0x11460")
    parser.add_argument("--func-name", required=True, help="函数名，例如 sub_11460")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = define_driver_dispatch({"address": args.address, "func_name": args.func_name})
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
