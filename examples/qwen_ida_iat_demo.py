"""Qwen3 + IDA Pro MCP 最小示例，用于列出 IAT 导入表。

运行此脚本前请确保：
  * 已安装 qwen-agent (`pip install qwen-agent`)
  * IDA Pro MCP 服务器在磁盘上可用
  * IDA Pro 已打开并加载了目标二进制文件（MCP 服务器与运行的 IDA 实例通信）

在运行脚本前，请设置环境变量 `QWEN_API_KEY`（或编辑下面的 `llm_cfg` 结构）
填入您的 Model Studio/OpenAI 兼容密钥。
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from qwen_agent.agents import Assistant


def build_llm_cfg() -> Dict[str, Any]:
    """返回 Assistant 使用的 Qwen3 模型配置。"""

    return {
        "model": "qwen-max",
        "model_server": "https://dashscope.aliyuncs.com/compatible-mode/v1/",
        "api_key": os.environ["QWEN_API_KEY"],
    }


def build_tools_cfg() -> List[Any]:
    """返回暴露 IDA Pro 功能的 MCP 工具配置。"""

    ida_python = os.getenv(
        "IDA_PYTHON_EXE",
        r"D:\\tools\\IDA9.1\\python311\\python.exe",
    )
    ida_server_script = os.getenv(
        "IDA_MCP_SERVER",
        r"D:\\tools\\IDA9.1\\python311\\Lib\\site-packages\\ida_pro_mcp\\server.py",
    )

    return [
        {
            "mcpServers": {
                "ida_pro": {
                    "type": "stdio",
                    "command": ida_python,
                    "args": [ida_server_script],
                    "description": "通过 stdio 暴露的 IDA Pro MCP 服务器",
                }
            }
        },
        "code_interpreter",
    ]


def main() -> None:
    llm_cfg = build_llm_cfg()
    tools_cfg = build_tools_cfg()

    bot = Assistant(llm=llm_cfg, function_list=tools_cfg)

    messages = [
        {
            "role": "system",
            "content": (
                "你是一个Windows驱动逆向工程师，你可以通过ida_pro mcp操作IDA。"
            ),
        },
        {
            "role": "user",
            "content": (
                "连接到 ida_pro MCP 服务器并枚举导入地址表 (IAT) 中引用的每个导入。"
                "返回每个条目的模块名、函数名和地址。将结果格式化为 Markdown 表格。"
            ),
        },
    ]

    max_resp_len = 0
    for responses in bot.run(messages=messages):
        pass

    print("\nQwen3 的最终响应:")
    # print(responses)
    for resp in responses:
        role = resp.get("role","")

        function_call = resp.get("function_call", {})
        if len(function_call) > 0:
            func_name = function_call.get("name", "")
            func_args = function_call.get("args", '')
            print(f"调用工具：{func_name}({func_args})")

        content = resp.get("content", "")
        if len(content) > 0:
            if role == "function":
                func_name = function_call.get("name", "")
                print(f"MCP({func_name})返回：")
            print(content, end="")


if __name__ == "__main__":
    main()