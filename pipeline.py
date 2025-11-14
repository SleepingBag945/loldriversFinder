#!/usr/bin/env python3
"""IoCreateDevice 引用分析调度程序。

执行步骤：
1. 使用 examples.find_iocreatedevice_refs 获取所有引用 IoCreateDevice 的函数 (funcs1)。
2. 对每个函数调用 examples.analyze_major_function，得到 DriverObject->MajorFunction[14] 的目标函数 (func2)。
3. 调用 examples.list_subfunctions 列出 func2 的直接子函数 (func3)。
4. 对 func3 中的外部函数，使用 examples.describe_external_function 获取定义/描述；
   对内部函数，使用 examples.describe_internal_function 获取定义/描述。
   若描述中包含 “# MEM #” 或 “# MAP #” 标记，则追加 examples.analyze_memory_param 的 Markdown。
5. 在确认 func2 后，依次调用 examples.rename_iocontrol_code 与 examples.define_driver_dispatch，
   统一 IoControlCode 局部变量与函数原型。
6. 将 func3 描述与 func2 的 analyze_memory_param、examples.analyze_irp_memory_access 结果整合成 Markdown，
   便于拼接进 AI 上下文，并辅助后续深度思考分析。
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from examples.analyze_major_function import analyze_major_function_target
from examples.analyze_irp_memory_access import analyze_irp_memory_access
from examples.analyze_memory_param import analyze_memory_param_markdown
from examples.describe_external_function import describe_external_function
from examples.describe_internal_function import describe_internal_function
from examples.define_driver_dispatch import define_driver_dispatch
from examples.find_iocreatedevice_refs import find_iocreatedevice_refs
from examples.list_subfunctions import list_subfunctions
from examples.rename_iocontrol_code import rename_io_control_code

MEMORY_MARKERS: Tuple[str, ...] = ("# MEM #", "# MAP #")


def log_step(message: str) -> None:
    RED = "\033[31m"
    RESET = "\033[0m"
    print(f"{RED}[+] {message}{RESET}", flush=True)


def print_block(title: str, content: str) -> None:
    print(f"\n[=] {title}\n{content}\n", flush=True)


def dedupe_functions(
    entries: Sequence[Dict[str, str]], name_key: str = "func_name", addr_key: str = "address"
) -> List[Dict[str, str]]:
    """根据名称 + 地址去重，保持原始顺序。"""

    seen = set()
    deduped: List[Dict[str, str]] = []
    for entry in entries:
        name = entry.get(name_key)
        addr = entry.get(addr_key)
        if not name or not addr:
            continue
        key = (name.lower(), addr.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def has_memory_marker(text: str) -> bool:
    return any(marker in text for marker in MEMORY_MARKERS)


def describe_child(child: Dict[str, str]) -> Tuple[str, str]:
    """获取子函数描述，必要时追加内存参数分析并返回代码片段。"""

    name = child.get("name", "unknown")
    log_step(f"生成子函数描述：{name}")

    if child.get("type") == "external":
        log_step(f"调用 describe_external_function 获取 {name} 描述")
        desc = describe_external_function(
            {"address": child["address"], "name": child["name"]}
        )
        print_block(f"{name} 描述（external）", desc)
        log_step(f"外部函数 {name} 描述完成")
        return desc, ""

    log_step(f"调用 describe_internal_function 获取 {name} 描述")
    desc = describe_internal_function(
        {"address": child["address"], "name": child["name"]}
    )
    print_block(f"{name} 描述（internal）", desc)
    log_step(f"内部函数 {name} 描述完成")

    mem_code = ""
    if has_memory_marker(desc):
        log_step(f"{name} 包含内存标记，追加 analyze_memory_param 结果")
        mem_md = analyze_memory_param_markdown(
            {"address": child["address"], "func_name": child["name"]}
        )
        print_block(f"{name} 内存参数分析（child）", mem_md)
        desc = f"{desc}\n\n---\n{mem_md}"
        mem_code = mem_md
        log_step(f"{name} 内存参数分析完成")

    return desc, mem_code


def format_child_section(child: Dict[str, str], description: str) -> str:
    name = child.get("name", "unknown")
    addr = child.get("address", "N/A")
    func_type = child.get("type", "internal")
    header = f"#### {name} ({func_type})\n- 地址：`{addr}`"
    return f"{header}\n\n{description.strip()}"


def analyze_parent_memory(target: Dict[str, str]) -> str:
    log_step(f"分析函数内存参数：{target.get('func_name')} ({target.get('address')})")
    try:
        log_step("调用 analyze_memory_param_markdown")
        result = analyze_memory_param_markdown(target)
        print_block(
            f"{target.get('func_name')} 内存参数分析（parent）",
            result,
        )
        log_step(f"内存参数分析完成：{target.get('func_name')}")
        return result
    except Exception:
        logging.exception(
            "analyze_memory_param_markdown 失败：%s @ %s",
            target.get("func_name"),
            target.get("address"),
        )
        return "（analyze_memory_param 运行失败）"


def analyze_irp_memory_section(
    target: Dict[str, str],
    context: str | None = None,
    transcript_sink: List[Dict[str, Any]] | None = None,
) -> str:
    log_step(f"分析 IRP 控制内存访问：{target.get('func_name')} ({target.get('address')})")
    try:
        log_step("调用 analyze_irp_memory_access")
        result = analyze_irp_memory_access(target, context, transcript_sink)
        print_block(
            f"{target.get('func_name')} IRP 控制内存访问",
            result,
        )
        log_step(f"IRP 控制内存访问分析完成：{target.get('func_name')}")
        return result
    except Exception:
        logging.exception(
            "analyze_irp_memory_access 失败：%s @ %s",
            target.get("func_name"),
            target.get("address"),
        )
        return "（IRP 控制内存访问分析失败）"


def process_major_function(
    caller: Dict[str, str], handler: Dict[str, str]
) -> Tuple[str, List[Dict[str, Any]], List[str]]:
    """收集单个 MajorFunction 处理函数的完整报告、IRP 对话与可控内存代码。"""

    handler_target = {"address": handler["address"], "func_name": handler["func_name"]}

    log_step(
        f"列出子函数：{handler.get('func_name')} ({handler.get('address')})"
    )
    try:
        log_step("调用 list_subfunctions")
        children = list_subfunctions(handler_target)
        print_block(
            f"{handler.get('func_name')} 子函数列表",
            json.dumps(children, ensure_ascii=False, indent=2),
        )
        log_step(f"子函数数量：{len(children)}")
    except Exception:
        logging.exception(
            "list_subfunctions 失败：%s @ %s",
            handler.get("func_name"),
            handler.get("address"),
        )
        log_step("子函数枚举失败，跳过描述")
        children = []

    child_sections: List[str] = []
    child_mem_codes: List[str] = []
    for child in children:
        try:
            desc, mem_code = describe_child(child)
        except Exception:
            logging.exception(
                "描述子函数失败：%s (%s)", child.get("name"), child.get("type")
            )
            log_step(f"子函数描述失败：{child.get('name')}")
            continue
        if mem_code:
            child_mem_codes.append(
                f"### {child.get('name')} 可控内存参数\n{mem_code.strip()}"
            )
        child_sections.append(format_child_section(child, desc))

    child_block = (
        "\n\n".join(child_sections) if child_sections else "（未获取到子函数描述）"
    )

    parent_mem_md = analyze_parent_memory(handler_target)
    combined_context_parts: List[str] = [
        "### 子函数描述\n",
        child_block,
        "\n### 函数内存参数分析\n",
        parent_mem_md,
    ]
    combined_context = "\n".join(part for part in combined_context_parts if part).strip()
    if child_mem_codes:
        combined_context = (
            combined_context
            + "\n\n### 可控内存参数代码\n"
            + "\n\n".join(child_mem_codes)
        )

    irp_transcripts: List[Dict[str, Any]] = []
    irp_md = analyze_irp_memory_section(
        handler_target,
        combined_context,
        transcript_sink=irp_transcripts,
    )

    report_lines = [
        f"### Caller: {caller.get('func_name')} @ `{caller.get('address')}`",
        "",
        f"**MajorFunction[14] 处理函数：** {handler.get('func_name')} @ `{handler.get('address')}`",
        "",
        "#### 子函数描述",
        child_block,
        "",
        "#### 函数内存参数分析",
        parent_mem_md,
        "",
        "#### IRP 控制内存访问",
        irp_md,
    ]

    return "\n".join(report_lines).strip(), irp_transcripts, child_mem_codes


def build_deep_reasoning_prompt(
    transcripts: Sequence[Dict[str, Any]],
    mem_code_sections: Sequence[str],
) -> str:
    lines: List[str] = [
        "你将收到多段与 Windows 驱动 IRP 控制内存访问分析相关的对话记录。",
        "这些记录包含提示词与来自 IDA MCP 的响应，请在不依赖 MCP 的情况下进行更深入的思考。",
        "任务：",
        "1. 归纳每个函数中可能被 Irp->SystemBuffer 或相关字段控制的读/写位置。",
        "2. 根据 IoControlCode 分支梳理潜在风险场景，并指出是否需要额外验证。",
        "3. 给出进一步人工分析或利用所需的关键信息清单。",
        """4. 一下是IRP结构以及可被用户控制的情况。typedef struct _IRP_LAYOUT64 {
      CSHORT              Type;             // 0x000 内核设定，不可控
      USHORT              Size;             // 0x002 内核设定
      PMDL                MdlAddress;       // 0x008 指针不可控；所映射的用户缓冲区内容可控
      ULONG               Flags;            // 0x010 内核/驱动控制
      union {
          struct _IRP    *MasterIrp;        // 0x018 不可控
          volatile LONG   IrpCount;         // 0x018 不可控
          PVOID           SystemBuffer;     // 0x018 METHOD_BUFFERED 时内容可控
      } AssociatedIrp;
      LIST_ENTRY          ThreadListEntry;  // 0x020 内核队列链接，不可控
      IO_STATUS_BLOCK     IoStatus;         // 0x030 驱动/内核写
      KPROCESSOR_MODE     RequestorMode;    // 0x040 内核填充，反映 UserMode/KernelMode
      BOOLEAN             PendingReturned;  // 0x041 内核
      CHAR                StackCount;       // 0x042 内核
      CHAR                CurrentLocation;  // 0x043 内核
      BOOLEAN             Cancel;           // 0x044 内核
      KIRQL               CancelIrql;       // 0x045 内核
      CCHAR               ApcEnvironment;   // 0x046 内核
      UCHAR               AllocationFlags;  // 0x047 内核
      union {
          PIO_STATUS_BLOCK UserIosb;        // 0x048 指针源自用户调用，可控
          PVOID            IoRingContext;   // 0x048 指针源自用户 IoRing，可控
      };
      PKEVENT             UserEvent;        // 0x050 指针来自用户句柄，可控
      union {
          struct {
              union {
                  PIO_APC_ROUTINE UserApcRoutine; // 0x058 指针可控
                  PVOID           IssuingProcess;  // 0x058 IoRing 场景下可控
              };
              union {
                  PVOID           UserApcContext;  // 0x060 指针可控
                  struct _IORING_OBJECT *IoRing;   // 0x060 指向用户 IoRing
              };
          } AsynchronousParameters;
          LARGE_INTEGER    AllocationSize;  // 0x058 某些请求直接来自用户输入
      } Overlay;
      volatile PDRIVER_CANCEL CancelRoutine; // 0x068 驱动设置
      PVOID               UserBuffer;        // 0x070 指针/内容来自用户（直接 I/O）
      union {
          struct {
              union {
                  KDEVICE_QUEUE_ENTRY DeviceQueueEntry; // 0x078 内核
                  struct {
                      PVOID DriverContext[4];           // 0x078 驱动使用
                  };
              };
              PETHREAD        Thread;        // 0x098 发起线程的引用，不可篡改
              PCHAR           AuxiliaryBuffer; // 0x0A0 内核缓冲区
              struct {
                  LIST_ENTRY  ListEntry;     // 0x0A8 内核
                  union {
                      PIO_STACK_LOCATION CurrentStackLocation; // 0x0B8 指针内核控制，但其中参数值源自用户
                      ULONG              PacketType;           // 0x0B8 内核
                  };
              } Overlay;
              PFILE_OBJECT    OriginalFileObject; // 0x0C0 指向用户句柄解析出的对象，指针不可控
          } Overlay;
          KAPC               Apc;            // 0x078 内核使用
          PVOID              CompletionKey;  // 0x078 内核/驱动使用
      } Tail;
  } IRP_LAYOUT64;""",
        "",
        "以下是原始对话：",
    ]
    for idx, payload in enumerate(transcripts, 1):
        target = payload.get("target", {})
        func_name = target.get("func_name", "unknown")
        address = target.get("address", "N/A")
        lines.append(f"\n## 对话 {idx}: {func_name} @ {address}")
        lines.append("### Prompt")
        lines.append(json.dumps(payload.get("messages", []), ensure_ascii=False, indent=2))
        lines.append("### MCP Responses")
        lines.append(json.dumps(payload.get("responses", []), ensure_ascii=False, indent=2))
    if mem_code_sections:
        lines.append("\n## 可控内存参数代码摘录")
        lines.append("\n\n".join(mem_code_sections))

    lines.append(
        "\n请输出 Markdown，包含“总结”“IoControlCode 风险”“两个小节。"
    )
    return "\n".join(lines)


def _stringify_stream_field(field: Any) -> str:
    if field is None:
        return ""
    if isinstance(field, str):
        return field
    if isinstance(field, list):
        parts: List[str] = []
        for item in field:
            if isinstance(item, dict):
                text = (
                    item.get("text")
                    or item.get("content")
                    or item.get("data")
                    or ""
                )
                if not isinstance(text, str):
                    text = json.dumps(text, ensure_ascii=False)
                parts.append(text)
            else:
                parts.append(_stringify_stream_field(item))
        return "".join(parts)
    if isinstance(field, dict):
        text = field.get("text") or field.get("content")
        if isinstance(text, str):
            return text
        if text:
            return _stringify_stream_field(text)
        return json.dumps(field, ensure_ascii=False)
    return str(field)


def run_deep_reasoning(
    transcripts: Sequence[Dict[str, Any]],
    mem_code_sections: Sequence[str],
) -> str:
    if not transcripts:
        log_step("未捕获到 IRP 对话，跳过深度思考分析")
        return ""

    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        logging.exception("缺少 openai 库，无法执行深度思考分析")
        return ""

    api_key = os.getenv("DASHSCOPE_API_KEY")
    if not api_key:
        logging.warning("未设置 DASHSCOPE_API_KEY，跳过深度思考分析")
        return ""

    prompt = build_deep_reasoning_prompt(transcripts, mem_code_sections)
    client = OpenAI(api_key=api_key, base_url="https://dashscope.aliyuncs.com/compatible-mode/v1")

    log_step("调用 deepseek-v3.2-exp 执行脱离 MCP 的深度思考分析（流式输出）")
    try:
        stream = client.chat.completions.create(
            model="deepseek-v3.2-exp",
            messages=[
                {
                    "role": "system",
                    "content": "You are a meticulous Windows driver analyst. Think deeply and cite evidence.",
                },
                {"role": "user", "content": prompt},
            ],
            stream=True,
            stream_options={"include_usage": True},
            extra_body={"enable_thinking": True},
        )
    except Exception:
        logging.exception("调用 deepseek-v3.2-exp 失败")
        return ""

    print("\n[=] 深度思考输出（deepseek-v3.2-exp）\n")
    print("=" * 20 + "思考过程" + "=" * 20 + "\n")
    reasoning_parts: List[str] = []
    answer_parts: List[str] = []
    is_answering = False
    try:
        for chunk in stream:
            choices = getattr(chunk, "choices", None)
            if not choices:
                usage = getattr(chunk, "usage", None)
                if usage:
                    print("\nUsage:")
                    print(usage)
                continue
            delta = getattr(choices[0], "delta", None)
            if not delta:
                continue
            thinking = _stringify_stream_field(getattr(delta, "reasoning_content", None))
            if not thinking:
                thinking = _stringify_stream_field(getattr(delta, "thinking", None))
            if thinking:
                if not is_answering:
                    print(thinking, end="", flush=True)
                reasoning_parts.append(thinking)
            content = _stringify_stream_field(getattr(delta, "content", None))
            if content:
                if not is_answering:
                    print("\n" + "=" * 20 + "完整回复" + "=" * 20 + "\n")
                    is_answering = True
                print(content, end="", flush=True)
                answer_parts.append(content)
    except Exception:
        logging.exception("流式读取 deepseek-v3.2-exp 输出失败")
    finally:
        print("\n\n[=] 深度思考分析完成\n")
    reasoning_text = "".join(reasoning_parts).strip()
    answer_text = "".join(answer_parts).strip()
    combined_sections = [
        "### 思考过程",
        reasoning_text or "（无思考内容）",
        "### 完整回复",
        answer_text or "（无正式回复）",
    ]
    return "\n\n".join(combined_sections).strip()


def write_result_report(
    report_md: str,
    deep_md: str,
    mem_code_sections: Sequence[str],
) -> None:
    timestamp = int(time.time())
    report_name = f"{timestamp}.md"
    path = Path(report_name)
    lines: List[str] = []
    main_content = report_md.strip()
    if main_content:
        lines.append(main_content)
    lines.append("## 深度思考输出")
    deep_section = deep_md.strip()
    if deep_section:
        lines.append(deep_section)
    else:
        lines.append("（未生成深度思考结果）")
    if mem_code_sections:
        lines.append("## 可控内存参数代码汇总")
        lines.append("\n\n".join(mem_code_sections))

    path.write_text("\n\n".join(lines).strip() + "\n", encoding="utf-8")
    log_step(f"结果报告已写入 {report_name}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="[*] %(message)s")

    log_step("开始查找 IoCreateDevice 引用")
    callers = dedupe_functions(find_iocreatedevice_refs())
    log_step(f"共找到 {len(callers)} 个引用函数")
    if not callers:
        print("未找到 IoCreateDevice 引用函数。")
        return

    reports: List[str] = []
    all_transcripts: List[Dict[str, Any]] = []
    all_mem_codes: List[str] = []

    for idx, caller in enumerate(callers, 1):
        log_step(
            f"[{idx}/{len(callers)}] 处理引用函数：{caller.get('func_name')} ({caller.get('address')})"
        )
        try:
            log_step("调用 analyze_major_function_target")
            handler = analyze_major_function_target(caller)
            log_step(
                f"MajorFunction[14] 解析完成：{handler.get('func_name')} ({handler.get('address')})"
            )
        except Exception:
            logging.exception(
                "analyze_major_function_target 失败：%s @ %s",
                caller.get("func_name"),
                caller.get("address"),
            )
            log_step("MajorFunction 分析失败，跳过该调用者")
            continue

        log_step(
            f"调用 rename_io_control_code：{handler.get('func_name')} ({handler.get('address')})"
        )
        try:
            rename_result = rename_io_control_code(
                {"address": handler["address"], "func_name": handler["func_name"]}
            )
            print_block(
                f"{handler.get('func_name')} IoControlCode 重命名结果",
                json.dumps(rename_result, ensure_ascii=False, indent=2),
            )
            log_step("IoControlCode 重命名完成")
        except Exception:
            logging.exception(
                "rename_io_control_code 失败：%s @ %s",
                handler.get("func_name"),
                handler.get("address"),
            )
            log_step("IoControlCode 重命名失败，继续后续分析")

        log_step(
            f"调用 define_driver_dispatch：{handler.get('func_name')} ({handler.get('address')})"
        )
        try:
            proto_result = define_driver_dispatch(
                {"address": handler["address"], "func_name": handler["func_name"]}
            )
            print_block(
                f"{handler.get('func_name')} 函数原型设置结果",
                json.dumps(proto_result, ensure_ascii=False, indent=2),
            )
            log_step("DriverDispatch 原型设置完成")
        except Exception:
            logging.exception(
                "define_driver_dispatch 失败：%s @ %s",
                handler.get("func_name"),
                handler.get("address"),
            )
            log_step("函数原型设置失败，继续后续分析")

        report, transcripts, mem_codes = process_major_function(caller, handler)
        reports.append(report)
        all_transcripts.extend(transcripts)
        all_mem_codes.extend(mem_codes)
        log_step(f"调用者处理完成：{caller.get('func_name')}")

    final_output = "# IoCreateDevice 调度分析报告\n\n" + "\n\n---\n\n".join(reports)
    print(final_output)

    deep_reasoning_md = run_deep_reasoning(all_transcripts, all_mem_codes)
    write_result_report(final_output, deep_reasoning_md, all_mem_codes)


if __name__ == "__main__":
    main()
