---
id: defense-detection-etw-keylogger-api-behavior
title: 基于 ETW API 行为监控检测键盘记录器：GetAsyncKeyState/SetWindowsHookEx/RegisterRawInputDevices 的参数、调用栈与进程签名
type: scenario
domain: defense
path: defense/detection
technique: etw-keylogger-api-behavior-detection
aliases:
- Elastic Defend 键盘记录检测
- Keystroke Input Capture 检测
- ETW API 行为检测
- GetAsyncKeyState 监控
- SetWindowsHookEx 钩子检测
- RegisterRawInputDevices 监控
- 键盘记录器检测规则
tags:
- defense
- detection
- etw
- keylogger
- windows
- edr
- behavior
- api-monitoring
- elastic
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V332
  verified_at: '2026-11-08T18:04:28+08:00'
  notes: 已对照原文及 4 张图核对：KQL 规则、ECS 字段表、Kibana 告警截图（3 条 Critical，host desktop-rnm57kt，user vagrant，Keylogger.exe，risk 99；Discover 6 条 RegisterRawInputDevices 事件 JSON）均一致；Elastic Defend 8.12+ 为功能引入版本非漏洞受影响版本，已 clear。未在本机执行 KQL/样本。
---

## 一句话结论

Elastic Defend 8.12+ 通过 ETW 采集 Windows API 调用的名称、参数、返回值、调用栈与模块签名状态，对 `GetAsyncKeyState`、`SetWindowsHookEx`、`RegisterRawInputDevices` 等键盘记录相关 API 做行为规则匹配；即使没有恶意样本签名，也能从轮询节奏、钩子类型、Raw Input 的 `KEYBOARD`+`INPUTSINK` 参数和不可信调用栈检出键盘记录器，并在 Kibana 中给出可调查的 API 调用文档。

## 原理

- **ETW API 遥测**：Elastic Defend 使用 Windows 事件跟踪（ETW）记录进程对敏感 API 的调用，字段包括 `process.Ext.api.name`、`process.Ext.api.parameters.*`、`process.Ext.api.metadata.*`、`process.thread.Ext.call_stack_summary`、`process.code_signature.status` 等；这比只依赖文件哈希/签名更接近行为本质。
- **不同类型键盘记录器的判别参数**：
  - `GetAsyncKeyState`：`process.Ext.api.metadata.ms_since_last_keyevent`（距上次按键事件毫秒数）与 `background_callcount`（两次成功调用之间的总调用次数，含失败）可暴露“高频遍历虚拟键码”的轮询循环。
  - `SetWindowsHookEx`：`parameters.hook_type`（如 `WH_KEYBOARD_LL`）、`parameters.hook_module`（钩子 DLL 路径）、`parameters.procedure`（钩子过程地址）、`metadata.procedure_symbol` 可识别低级键盘钩子及未签名/可疑模块。
  - `RegisterRawInputDevices`：`parameters.usage_page`（`GENERIC`）、`parameters.usage`（`KEYBOARD`）、`parameters.flags`（`INPUTSINK` 表示后台接收）、`metadata.return_value`、`windows_count`/`visible_windows_count`/`thread_info_flags`、`start_address_module`、`start_address_allocation_protection` 可区分合法输入设备与恶意捕获。
  - DirectInput 键盘记录最终也会落到相关输入 API，可用调用栈（`dinput8.dll` 等）与模块签名辅助识别。
- **规则逻辑**：以 `RegisterRawInputDevices` 为例，命中条件同时要求 API 名匹配、进程代码签名不是 `trusted`、参数含键盘 usage 与 `INPUTSINK`、`thread.Ext.call_stack_summary` 非空、最终用户模块哈希存在，且最终模块路径不在系统目录/Program Files 等白名单、进程可执行文件不在 Program Files；这样把大量正常输入设备/远程支持软件排除，降低误报。
- **为什么有效**：键盘记录必须调用这些会改变输入处理链的 API；API 参数和调用栈由内核/ETW 记录，不易被普通用户态样本伪造（除非主动篡改 ETW，见防御边界）。即使样本加密、无签名、内存加载，行为仍暴露。

## 触发条件

- 端点安装并启用 Elastic Defend 8.12+（或具备类似 ETW API 遥测的 EDR），相关键盘记录检测规则已启用。
- 恶意进程以非可信签名/未签名模块调用 `GetAsyncKeyState`、`SetWindowsHookEx(WH_KEYBOARD_LL)` 或 `RegisterRawInputDevices`，参数符合键盘捕获特征。
- ETW 未被攻击者关闭/篡改，`process.thread.Ext.call_stack_*` 等字段能正常采集。

## 检测步骤

1. 部署/确认 EDR 的 API 行为遥测与键盘记录规则（Elastic 提供 `collection_getasynckeystate_*`、`collection_keystroke_input_capture_via_registerrawinputdevices`、`collection_keystroke_messages_hooking_via_setwindowshookex`、`collection_keystroke_input_capture_from_*` 等规则）。
2. 在测试环境运行一个仅用于验证的 Raw Input 键盘记录 PoC（如 `keylogger.exe`），观察端点弹窗 “Malicious Behavior Detection Alert: Keystroke Input Capture via RegisterRawInputDevices”。
3. 在 Kibana 的 Security → Alerts 查看告警（rule name、host、process.executable、risk score），并打开对应文档的 JSON。
4. 检查 API 文档中的关键字段：`process.Ext.api.name`、`parameters.usage`/`usage_page`/`flags`、`start_address_module`、`thread_info_flags`、`windows_count`、调用栈与模块签名。
5. 结合进程树、持久化、文件写入和网络外传行为复核；对已知输入设备/远程支持软件（如 Teams、KumoSpace）按原文白名单思路调优，避免误报。
6. 若确认恶意，隔离主机、提取样本与 API 调用日志、排查凭据是否已被外传。

## PoC

文章给出的 Raw Input 检测 KQL 规则（节选，字段来自 Elastic ECS）：

```text
api where
 process.Ext.api.name == "RegisterRawInputDevices" and not process.code_signature.status : "trusted" and
 process.Ext.api.parameters.usage : ("HID_USAGE_GENERIC_KEYBOARD", "KEYBOARD") and
 process.Ext.api.parameters.flags : "*INPUTSINK*" and process.thread.Ext.call_stack_summary : "?*" and
 process.thread.Ext.call_stack_final_user_module.hash.sha256 != null and process.executable != null and
 not process.thread.Ext.call_stack_final_user_module.path :
   ("*\\program files*", "*\\windows\\system32\\*", "*\\windows\\syswow64\\*", "*\\windows\\systemapps\\*",
    "*\\users\\*\\appdata\\local\\*\\kumospace.exe", "*\\users\\*\\appdata\\local\\microsoft\\teams\\current\\teams.exe") and
 not process.executable : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe")
```

告警文档示例（节选）：`process.Ext.api.name = "RegisterRawInputDevices"`，`parameters.usage = "KEYBOARD"`、`usage_page = "GENERIC"`、`flags = "INPUTSINK"`、`return_value = 1`，`start_address_module = "C:\\Users\\vagrant\\Keylogger.exe"`，`windows_count = 2`、`visible_windows_count = 0`、`thread_info_flags = 16`。

该规则/查询未在本机执行（文章为不可信数据，未运行其中任何代码）。

## 变体与关联

- `GetAsyncKeyState` 轮询检测：用 `ms_since_last_keyevent` 很小、`background_callcount` 很大（如 6021）判断高频轮询循环，而非正常输入软件。
- `SetWindowsHookEx` 检测：`hook_type=WH_KEYBOARD_LL`、钩子模块未签名/位于用户可写目录、`procedure` 指向非系统模块。
- 托管应用/未签名 DLL/可疑调用栈变体：Elastic 提供 `Keystrokes Input Capture from a Managed Application`、`... from Unsigned DLL`、`... from Suspicious CallStack` 等规则。
- 关联攻击侧实现：[[pentest-c2-keylogger-getasynckeystate-polling]]、[[pentest-c2-keylogger-setwindowshookex-wh-keyboard-ll]]、[[pentest-c2-keylogger-rawinput-registerrawinputdevices]]、[[pentest-c2-keylogger-directinput-getdevicestate]]（四类 API 的实现与参数）。
- 相关取证卡：[[defense-forensics-snake-keylogger-stealer-collection-exfil-channels]]（SetWindowsHookEx 键盘记录与多通道外传）、[[defense-forensics-silverfox-winos4-file-registry-artifact-dump]]（DirectInput 键盘记录痕迹）。
- 边界：攻击者可 patch `ntdll!EtwEventWrite` 或卸载 ETW provider 致盲用户态 ETW；此时需结合内核回调、网络/文件行为、内存扫描与 PPL 保护等。

## 检测与防御

- **启用行为遥测**：使用支持 ETW API + 调用栈 + 签名状态的 EDR，并保持规则更新；不要只依赖哈希/签名。
- **规则调优**：对合法输入设备、远程支持、输入法、Teams/KumoSpace 等建立白名单；同时保留对白名单的审计，防止被滥用。
- **防 ETW 篡改**：监控 `EtwEventWrite` 补丁、ETW provider 异常关闭；启用内核态遥测与受保护进程；限制调试权限。
- **纵深防御**：应用白名单/签名强制、禁止未签名 DLL 与用户目录可执行文件运行；结合网络外传、文件日志、持久化行为做关联告警；对键盘记录告警优先检查凭据泄露并强制改密/吊销会话。
