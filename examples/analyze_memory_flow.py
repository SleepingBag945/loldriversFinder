"""分析函数参数对内存地址控制流的模块。"""

from __future__ import annotations

import argparse
import logging
from typing import Any, Dict, List, Sequence

from qwen_agent.agents import Assistant

try:
    from .agent_config import build_llm_cfg, build_tools_cfg
except ImportError:  # pragma: no cover - executed when run as script
    from agent_config import build_llm_cfg, build_tools_cfg


def build_messages(target: Dict[str, str]) -> List[Dict[str, str]]:
    """构造提示词，要求助手输出参数传递流的 Markdown 描述。"""

    func_name = target["func_name"]
    address = target["address"]

    user_goal = (
        f"请在 IDA 中分析函数 {func_name}（地址 {address}），重点追踪能够控制内存访问/复制目标的参数传递流。\n"
        "步骤：\n"
        "1. 调用 ida_pro-decompile_function（address/func_name 与上述匹配）获取伪代码。\n"
        "2. 标识所有涉及内存读写/复制/初始化的操作（例如 memcpy/memmove/Rtl*Memory、memset、自实现循环等）。\n"
        "3. 对每个操作，追踪其涉及的地址计算，明确是否由函数参数直接或间接提供；若涉及结构字段、局部变量或子函数调用，也需简述路径。\n"
        "4. 输出 Markdown，格式：\n"
        "   # <函数名> 参数内存地址传递流\n"
        "   - 地址：`0x...`\n"
        "   - 结论：存在/不存在可控参数\n"
        "   ## 参数路径\n"
        "   | 参数 | 操作类型 | 传递路径 | 证据 |\n"
        "   | --- | --- | --- | --- |\n"
        "   若不存在此类参数，写“未检测到参数控制内存地址”。\n"
        "5. 严禁输出额外解释或前后缀。"
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
    """返回助手输出的 Markdown。"""

    assistant_contents = [
        resp.get("content", "") for resp in responses if resp.get("role") == "assistant"
    ]
    if not assistant_contents:
        raise RuntimeError("未收到助手输出")
    return assistant_contents[-1].strip()


def analyze_memory_flow(target: Dict[str, str]) -> str:
    """分析参数传递流并返回 Markdown。"""

    if "address" not in target or "func_name" not in target:
        raise ValueError("target 必须包含 address 与 func_name 键")

    logging.getLogger().setLevel(logging.WARNING)

    bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
    messages = build_messages(target)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    return extract_markdown(final_responses)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="分析参数对内存地址的传递流")
    parser.add_argument("--address", required=True, help="函数起始地址")
    parser.add_argument("--name", required=True, help="函数名称")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    markdown = analyze_memory_flow({"address": args.address, "func_name": args.name})
    print(markdown)


if __name__ == "__main__":
    main()

