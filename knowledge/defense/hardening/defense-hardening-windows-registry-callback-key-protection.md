---
id: defense-hardening-windows-registry-callback-key-protection
title: 驱动注册 RegistryCallback 拦截注册表键创建/重命名保护启动项
type: scenario
domain: defense
path: defense/hardening
technique: windows-registry-callback-protection
aliases:
- CmRegisterCallback 注册表保护
- RegistryCallback 拦截
- RegNtPreCreateKeyEx
- RegNtRenameKey
- 启动项保护
- FsRtlIsNameInExpression 通配符
tags:
- windows
- kernel-driver
- registry
- callback
- hardening
- persistence
- anti-tamper
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-16
  verified_at: '2026-11-08T07:51:56+08:00'
  notes: '已对照原文核对：CmRegisterCallback/RegistryCallback 原型、RegNtRenameKey 用 PREG_RENAME_KEY_INFORMATION.NewName、RegNtPreCreateKey(Ex) 用 PREG_CREATE_KEY_INFORMATION.CompleteName、FsRtlIsNameInExpression 通配符匹配与 STATUS_UNSUCCESSFUL 返回均与原文一致；图5 证实 regedit 手工新建先写【新项 #1】再重命名、被拦时报『注册表编辑器无法重命名 新项 #1』，故必须同时拦 RenameKey 的结论成立；图3 的 REG_NOTIFY_CLASS 表与卡内描述一致。未验证点：原文未给受影响版本（仅测试环境 win10），故 affected_versions 保持为空。'
---

## 一句话结论

`CmRegisterCallback` 注册的 `RegistryCallback` 能在注册表键创建/重名前拿到完整键名，对命中白名单模式的请求返回 `STATUS_UNSUCCESSFUL` 即可拒绝写入；由于图形界面新建键是"先建临时项再重命名"，只拦 `RegNtPreCreateKeyEx` 会漏，必须同时拦 `RegNtRenameKey`。

## 原理

- `CmRegisterCallback(Function, Context, &Cookie)` 把回调插入注册表操作路径，每个键操作都会以 `Argument1`=操作类型（`REG_NOTIFY_CLASS`）、`Argument2`=对应信息结构调用回调；返回非成功状态即让本次操作失败。
- `RegNtPreCreateKey/RegNtPreCreateKeyEx` 的 `Argument2` 是 `PREG_CREATE_KEY_INFORMATION`，`CompleteName` 为完整键路径（`\Registry\Machine\...`）；`RegNtRenameKey` 是 `PREG_RENAME_KEY_INFORMATION`，`NewName` 为新键名。
- 匹配用 `FsRtlIsNameInExpression(pattern, name, TRUE, NULL)`：大小写不敏感的通配符匹配（`*` 任意串、`?` 单字符），因此"只保护某一个键名"可以用 `*目标键名` 表达，避免写死完整路径。
- 为什么必须两个点都拦：`regedit`/多数程序"新建项"时先创建 `新项 #1` 之类的合法名字，再发起重命名到目标名。创建点看到的名字不含目标串，检查通过；最终生效的名字只在重命名点出现。只挂钩创建点会"看起来生效、实际可绕过"。
- 返回 `STATUS_UNSUCCESSFUL` 使操作失败但不影响系统稳定；失败信息直接返回给调用方（regedit 弹出"无法重命名"）。
- 边界：进程/线程创建、文件、网络各有独立回调，注册表回调只覆盖注册表写路径；拥有内核权限者可枚举并注销该回调（见关联卡），因此它是提高门槛而非安全边界。

## 触发条件

- 已加载注册表过滤/加固驱动，且 `DriverEntry` 中 `CmRegisterCallback` 成功、`DriverUnload` 中 `CmUnRegisterCallback(Cookie)` 正确注销。
- 保护模式串与目标键名匹配（`FsRtlIsNameInExpression` 语义）。
- 需要保护的对象是注册表路径类持久化（Run/RunOnce、服务、IFEO、Shell Extensions 等）。

## 利用步骤

1. 在 `DriverEntry` 中定义全局 `LARGE_INTEGER Cookie` 并注册 `CmRegisterCallback(RegistryCallback, NULL, &Cookie)`。
2. 回调中 `switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Argument1)`，处理 `RegNtRenameKey`、`RegNtPreCreateKey`、`RegNtPreCreateKeyEx`。
3. 对 `NewName`/`CompleteName` 用 `FsRtlIsNameInExpression(&pattern, name, TRUE, NULL)` 判断，命中返回 `STATUS_UNSUCCESSFUL` 并 `DbgPrint` 记录。
4. 卸载时 `CmUnRegisterCallback(Cookie)`，避免回调指向已卸载代码导致蓝屏。
5. 验证：用程序写注册表与手工在 regedit 新建目标键两种方式测试；只做第一种会误判防护有效。

## PoC

```c
LARGE_INTEGER Cookie = { 0 };

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    drv->DriverUnload = DrvUnload;
    return CmRegisterCallback(RegistryCallback, NULL, &Cookie);
}

NTSTATUS RegistryCallback(PVOID ctx, PVOID arg1, PVOID arg2) {
    UNREFERENCED_PARAMETER(ctx);
    UNICODE_STRING pat;
    RtlInitUnicodeString(&pat, L"*GSAHOJGHJERIWO");
    switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1) {
    case RegNtRenameKey: {
        PREG_RENAME_KEY_INFORMATION i = (PREG_RENAME_KEY_INFORMATION)arg2;
        if (i && i->NewName && FsRtlIsNameInExpression(&pat, i->NewName, TRUE, NULL))
            return STATUS_UNSUCCESSFUL;              // 手工新建走这里
        break;
    }
    case RegNtPreCreateKey:
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION i = (PREG_CREATE_KEY_INFORMATION)arg2;
        if (i && i->CompleteName && FsRtlIsNameInExpression(&pat, i->CompleteName, TRUE, NULL))
            return STATUS_UNSUCCESSFUL;              // 程序直接建同名键走这里
        break;
    }
    default: break;
    }
    return STATUS_SUCCESS;
}
```

## 变体与关联

- 变体：模式串换成完整路径前缀可精确保护 `\Registry\Machine\Software\...\Run`；也可只告警不拦截（返回成功 + 上报用户态）。
- 变体：改用 `CmRegisterCallbackEx` 可拿到 altitude 与驱动对象，便于与 minifilter 风格的分层注册统一管理。
- 变体：用户态持久化还可经服务、计划任务、WMI 订阅，注册表回调覆盖不到，需叠加其他监控。
- 关联：[[code-analysis-reverse-windows-cm-callback-list-enum-unregister]]（该保护可被枚举 Cookie 后注销）、[[defense-hardening-windows-kernel-process-protection-ob-callback]]（同族的进程/句柄保护实现）。

## 检测与防御

- 检测：对"注册表写入被拒绝"的告警要区分是策略拦截还是恶意驱动；监控非白名单驱动调用 `CmRegisterCallback`/`CmRegisterCallbackEx` 以及回调链表被摘除。
- 加固：开启驱动签名强制与 HVCI，限制未签名驱动加载；保护逻辑不要只依赖单一回调，叠加 ETW 与用户态完整性校验。
- 注意：回调运行在注册表操作上下文，不能做耗时或分页内存操作；必须正确处理 `DriverUnload` 注销，否则卸载后蓝屏。
