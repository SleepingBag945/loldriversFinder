"""Shared configuration helpers for Qwen + IDA MCP scripts."""

from __future__ import annotations

import os
from typing import Any, Dict, List


def build_llm_cfg() -> Dict[str, Any]:
    """Return the Qwen model configuration used by qwen-agent."""

    return {
        "model": "qwen-max",
        "model_server": "https://dashscope.aliyuncs.com/compatible-mode/v1/",
        "api_key": os.environ["QWEN_API_KEY"],
    }


def build_tools_cfg() -> List[Any]:
    """Return the MCP tool configuration exposing IDA Pro."""

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
