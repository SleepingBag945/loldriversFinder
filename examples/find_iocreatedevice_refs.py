"""自动查找 IoCreateDevice 引用的示例模块。

该脚本沿用 ``qwen_ida_iat_demo.py`` 的配置逻辑，但提示词改为：

1. 通过 IDA Pro MCP 的 ``list_imports`` 找到 IoCreateDevice 的导入地址。
2. 使用 ``get_xrefs_to`` 获取所有引用该导入的地址。
3. 判断这些引用属于哪些函数，并返回起始地址与函数名。

运行要求与 demo 相同：需要可用的 Qwen3 API 密钥、IDA Pro MCP 服务器路径、
以及一个已经加载目标二进制的 IDA 实例。
"""

from __future__ import annotations

import json
import logging
import time
import re
from typing import Any, Dict, List, Sequence

from qwen_agent.agents import Assistant

try:
    from .agent_config import build_llm_cfg, build_tools_cfg
except ImportError:  # pragma: no cover - executed when run as a script
    from agent_config import build_llm_cfg, build_tools_cfg


def build_messages() -> List[Dict[str, str]]:
    """构造驱动 Qwen3 的提示词，要求按步骤输出 JSON。"""

    user_goal = (
        "连接 ida_pro MCP 服务器，使用明确的工具调用完成以下任务：\n"
        "1. 调用 list_imports()，遍历导入表并找到 IoCreateDevice 的函数地址，记为 Addr。\n"
        "2. 对 Addr 调用 get_xrefs_to(Addr)，收集所有引用 IoCreateDevice 的地址列表 Addr2。\n"
        "3. 对每个 Addr2 调用 get_func_containing 或等价方法，确定其所在函数的起始地址与函数名。\n"
        "4. 仅返回 JSON 数组，数组元素形如 "
        '{"address":"0x140001000","func_name":"sub_140001000"}，'
        "按照地址去重并排序。禁止输出额外解释。"
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


JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", re.IGNORECASE)


def _load_json_array(text: str) -> List[Dict[str, str]] | None:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, list) else None


def extract_json_result(responses: Sequence[Dict[str, Any]]) -> List[Dict[str, str]]:
    """从助手回复中提取 JSON 并返回 Python 对象。"""

    assistant_contents = [
        resp.get("content", "") for resp in responses if resp.get("role") == "assistant"
    ]
    for raw in reversed(assistant_contents):
        raw = raw.strip()
        if not raw:
            continue

        parsed = _load_json_array(raw)
        if parsed is not None:
            return parsed

        # 查找 ```json ``` 代码块
        for block in JSON_BLOCK_RE.findall(raw):
            parsed = _load_json_array(block)
            if parsed is not None:
                return parsed

        # 尝试定位首尾方括号片段
        first = raw.find("[")
        last = raw.rfind("]")
        if first != -1 and last != -1 and last > first:
            parsed = _load_json_array(raw[first : last + 1])
            if parsed is not None:
                return parsed

    raise RuntimeError("未能从助手响应中解析到 JSON 列表")


def find_iocreatedevice_refs() -> List[Dict[str, str]]:
    """运行查询并返回 IoCreateDevice 引用函数列表，失败时自动重试。"""

    logging.getLogger().setLevel(logging.WARNING)

    for attempt in range(3):
        bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
        messages = build_messages()

        final_responses: List[Dict[str, Any]] = []
        for final_responses in bot.run(messages=messages):
            pass

        try:
            return extract_json_result(final_responses)
        except RuntimeError:
            print("\n[!] 解析 IoCreateDevice 引用 JSON 失败，打印助手响应以便排查：")
            for resp in final_responses:
                role = resp.get("role", "")
                content = resp.get("content", "")
                if content:
                    print(f"[role={role}] {content}")

            if attempt >= 2:
                raise

            wait_sec = 30
            print(f"[!] {wait_sec}s 后重试（剩余 {2 - attempt} 次）...")
            time.sleep(wait_sec)


def main() -> None:
    result = find_iocreatedevice_refs()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
