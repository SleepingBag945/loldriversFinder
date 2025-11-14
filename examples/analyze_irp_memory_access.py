"""分析函数中是否存在由 IRP 控制的内核内存读/写。"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from qwen_agent.agents import Assistant

try:
    from .agent_config import build_llm_cfg, build_tools_cfg
except ImportError:  # pragma: no cover - executed when run as script
    from agent_config import build_llm_cfg, build_tools_cfg


LOG_FILE_NAME = "logs.txt"


def save_transcript(
    target: Dict[str, str],
    messages: Sequence[Dict[str, str]],
    responses: Sequence[Dict[str, Any]],
) -> Dict[str, Any] | None:
    """持久化提示词与 MCP 响应，便于后续深度分析。"""

    try:
        timestamp = int(time.time())
        payload = {
            "target": target,
            "messages": list(messages),
            "responses": list(responses),
            "saved_at": timestamp,
        }
        log_path = Path.cwd() / LOG_FILE_NAME
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fp:
            fp.write(
                json.dumps(payload, ensure_ascii=False, indent=2)
                + "\n"
                + "-" * 80
                + "\n"
            )
        return payload
    except Exception:
        logging.exception("保存 IRP 分析对话失败")
        return None


def build_messages(
    target: Dict[str, str],
    context_markdown: str | None = None,
) -> List[Dict[str, str]]:
    """构造提示词，要求助手聚焦 IRP 控制的内存访问。"""

    func_name = target["func_name"]
    address = target["address"]

    irp_struct = (
        """typedef struct _IRP {
  CSHORT                    Type;
  USHORT                    Size;
  PMDL                      MdlAddress;
  ULONG                     Flags;
  union {
    struct _IRP     *MasterIrp;
    __volatile LONG IrpCount;
    PVOID           SystemBuffer;
  } AssociatedIrp;
  LIST_ENTRY                ThreadListEntry;
  IO_STATUS_BLOCK           IoStatus;
  KPROCESSOR_MODE           RequestorMode;
  BOOLEAN                   PendingReturned;
  CHAR                      StackCount;
  CHAR                      CurrentLocation;
  BOOLEAN                   Cancel;
  KIRQL                     CancelIrql;
  CCHAR                     ApcEnvironment;
  UCHAR                     AllocationFlags;
  union {
    PIO_STATUS_BLOCK UserIosb;
    PVOID            IoRingContext;
  };
  PKEVENT                   UserEvent;
  union {
    struct {
      union {
        PIO_APC_ROUTINE UserApcRoutine;
        PVOID           IssuingProcess;
      };
      union {
        PVOID                 UserApcContext;
#if ...
        _IORING_OBJECT        *IoRing;
#else
        struct _IORING_OBJECT *IoRing;
#endif
      };
    } AsynchronousParameters;
    LARGE_INTEGER AllocationSize;
  } Overlay;
  __volatile PDRIVER_CANCEL CancelRoutine;
  PVOID                     UserBuffer;
  union {
    struct {
      union {
        KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
        struct {
          PVOID DriverContext[4];
        };
      };
      PETHREAD     Thread;
      PCHAR        AuxiliaryBuffer;
      struct {
        LIST_ENTRY ListEntry;
        union {
          struct _IO_STACK_LOCATION *CurrentStackLocation;
          ULONG                     PacketType;
        };
      };
      PFILE_OBJECT OriginalFileObject;
    } Overlay;
    KAPC  Apc;
    PVOID CompletionKey;
  } Tail;
} IRP;"""
    )

    context_section = ""
    if context_markdown:
        context_section = (
            "\n附加上下文（来自外部/内部函数描述与之前的分析，可帮助减少幻觉）：\n"
            f"{context_markdown}\n"
            "在判断子函数或导入函数的行为时，必须优先引用以上内容，"
            "不要凭空推测未提供的细节。\n"
        )

    user_goal = (
        f"请在 IDA 中分析函数 {func_name}（地址 {address}），判断是否存在由 `IRP *Irp` 控制的 "
        "内核内存读/写操作。务必遵循以下步骤：\n"
        "1. 调用 ida_pro-decompile_function，address 与 func_name 必须与上述一致，以获取伪代码。\n"
        "2. 使用下列 IRP 结构参考理解层级（尤其是 AssociatedIrp.SystemBuffer）：\n"
        f"{irp_struct}\n"
        "3. 检查所有内存访问/复制/API 调用（如 memcpy/memmove/RtlCopyMemory/MmProbeAndLockPages、"
        "     自实现循环等），找出其中的指针（源或目标）是否最终来源于 `Irp` 或其嵌套字段\n"
        "     （例如 `Irp->AssociatedIrp.SystemBuffer`、`Irp->Tail.Overlay.CurrentStackLocation`、`Irp->UserBuffer`、"
        "      `Irp->Tail.Overlay.DriverContext[]` 等）。\n"
        "4. 对 `SystemBuffer`、`UserBuffer`、`MasterIrp`、`CurrentStackLocation->Parameters.DeviceIoControl`"
        "     等字段重点追踪，并结合 `IoControlCode` 的分支（switch/case 或 if）说明哪个控制码触发该路径。\n"
        "5. 只有当指针指向 `Irp` 之外的内核/用户缓冲区，且该指针可被来访者通过 `Irp` 结构控制时才算命中；"
        "     对 `Irp` 结构本身字段的读写不计入。\n"
        "6. 对每个命中，记录访问类型（read/write/copy/API）、指针角色（source/dest/other）、"
        "     指针的表达式路径、关联的 IoControlCode（若可确定），以及关键汇编/伪代码证据。\n"
        "7. 若命中路径依赖子函数或外部 API，请结合附加上下文给出的定义/描述进行判断，"
        "     严禁臆测未在上下文或伪代码中出现的行为。\n"
        "8. 输出 Markdown，格式：\n"
        f"   # {func_name} IRP 控制内存访问\n"
        f"   - 地址：`{address}`\n"
        "   - 判定：存在/不存在由 Irp 控制的内存访问\n"
        "   ## 证据\n"
        "   | 操作 | 角色 | 指针来源 | 关联 IoControlCode | 说明 |\n"
        "   | --- | --- | --- | --- | --- |\n"
        "   若未检测到，则在表格位置写“未发现由 Irp 控制的内存指针”。\n"
        f"{context_section}"
        "9. 禁止输出额外解释。"
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


def analyze_irp_memory_access(
    target: Dict[str, str],
    context_markdown: str | None = None,
    transcript_sink: List[Dict[str, Any]] | None = None,
) -> str:
    """分析目标函数的 IRP 控制内存访问情况。"""

    if "address" not in target or "func_name" not in target:
        raise ValueError("target 必须包含 address 与 func_name 键")

    logging.getLogger().setLevel(logging.WARNING)

    bot = Assistant(llm=build_llm_cfg(), function_list=build_tools_cfg())
    messages = build_messages(target, context_markdown)

    final_responses: List[Dict[str, Any]] = []
    for final_responses in bot.run(messages=messages):
        pass

    payload = save_transcript(target, messages, final_responses)
    if transcript_sink is not None and payload:
        transcript_sink.append(payload)

    return extract_markdown(final_responses)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="判定函数是否存在由 IRP 控制的内存读写"
    )
    parser.add_argument("--address", required=True, help="函数起始地址")
    parser.add_argument("--func-name", required=True, help="函数名称")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    markdown = analyze_irp_memory_access(
        {"address": args.address, "func_name": args.func_name}
    )
    print(markdown)


if __name__ == "__main__":
    main()
