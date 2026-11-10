---
id: code-analysis-reverse-anti-debug-common-app-process-whitelist
title: 反沙箱：常用软件进程白名单（QQ/微信/钉钉）全部缺失即判定云沙箱并退出
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: sandbox-common-app-process-whitelist
tags:
- anti-debug
- anti-sandbox
- windows
- process-enumeration
- toolhelp32
- evasion
- malware
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V282
  verified_at: '2026-11-08T05:42:36+08:00'
  notes: 已对照原文与5张截图核对：CreateToolhelp32Snapshot/Process32First/Next 遍历 szExeFile 白名单函数与原文一致；原文 main 两个分支均 return 0，按原样并不退出，卡已在原理/PoC 注明并补 ExitProcess(0)（含 dingtalk），confidence medium 合理。截图显示微步 fun.zip 0/28、Sigma Autorun Keys Modification，安恒判可疑、低危行为4项（打开/创建进程快照、遍历进程、读取RDP信息、注册表收集计算机名），说明样本在两个沙箱中均实际运行，原文『无法正常运行/成功绕过』缺少截图证据，卡按修正实现收录。dedup 候选均 related，无 dup-scan pair。未验证点：修正后代码未编译执行，实际绕过效果未复现。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-common-app-process-whitelist/
draft: false
kb_aliases:
- 常用软件进程白名单反沙箱
- QQ/微信/钉钉 进程检测
- 进程快照沙箱识别
- CreateToolhelp32Snapshot 白名单
- 云沙箱进程特征
---

## 一句话结论

恶意样本在入口用 `CreateToolhelp32Snapshot`/`Process32First/Next` 遍历进程，检查 QQ、微信、钉钉等常用软件是否有任意一个在运行；如果全部缺失，就判定当前是缺少日常软件的云沙箱并直接退出，从而不让沙箱观察到后续解密、外联、持久化等行为。

## 原理

- 云沙箱（文章测试微步 `s.threatbook.com` 与安恒 `sandbox.dbappsecurity.com.cn`）的镜像是为分析准备的干净环境，通常只预装系统组件和分析工具，不会运行 QQ、微信、钉钉这类面向真实用户的常驻软件；而国内真实办公/个人主机上这类进程很常见。
- `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` 取得全系统进程快照，`Process32First/Process32Next` 遍历 `PROCESSENTRY32.szExeFile`，逐个与白名单做字符串比较；任意命中即认为环境“像真实用户机”，全部未命中则 `ExitProcess(0)`/转入无害分支。
- 这种检查只读进程列表，不发起网络请求、不写注册表、不分配可执行内存，行为噪声低；相对“检测 VMware/VBox 进程/注册表”更贴近业务环境，沙箱若只伪装虚拟化痕迹仍会中招。代价是误杀：干净的个人机、服务器、精简系统可能本来就不运行这些软件。
- 文章给出的示例 `main` 把“未命中”和“命中”两个分支都写成 `return 0`，按原样编译时退出逻辑是空操作（无论是否命中都正常返回）；真正生效需要把未命中分支改成 `ExitProcess(0)`，或在命中后才进入恶意逻辑。本卡按后者描述，confidence 记为 medium。

## 触发条件

- Windows 目标，恶意代码能在解密/注入/外联等敏感动作之前执行环境检查。
- 沙箱镜像不运行 QQ/微信/钉钉等白名单软件（文章所称的两家云沙箱符合）。
- 攻击者选择的白名单与目标用户群体匹配（面向国内用户时可选 QQ/微信/钉钉；面向企业可选企业微信、钉钉、OA 客户端等）。
- 攻击者接受“真实用户没开这些软件就不运行”的误杀率。

## 利用步骤

1. 在入口点、任何敏感 API 之前调用进程快照；快照失败可按“疑似分析环境”处理或降级。
2. 遍历 `PROCESSENTRY32.szExeFile`，与白名单（`qq.exe`、`wechat.exe`、`dingtalk.exe` 等）做不区分大小写的比较；建议同时匹配进程描述/公司名，避免只改文件名绕过。
3. 若白名单一个都不在运行，`ExitProcess(0)` 或转入无害行为；若有命中，再解密 payload、注入、外联。
4. 可把白名单检查与其他低噪声信号（父进程、桌面文件数、uptime）组合，降低单一信号被沙箱预置软件绕过的风险。
5. 注意不要在检查阶段启动子进程或访问网络（如 `tasklist`、`curl`），这些本身会成为沙箱行为特征；应使用 Toolhelp32 快照在进程内完成。

## PoC

文章示例的进程遍历函数（保留原逻辑），并把退出分支改成真正退出：

```c
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>

static int is_process_running(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int found = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) { found = 1; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

int main(void) {
    if (!is_process_running("qq.exe") &&
        !is_process_running("wechat.exe") &&
        !is_process_running("dingtalk.exe")) {
        ExitProcess(0);          /* 白名单全部缺失：疑似云沙箱，退出 */
    }
    /* 命中任一常用软件后再执行恶意逻辑 */
    return 0;
}
```

说明：文章原示例两个分支都是 `return 0`，未真正实现退出；上述代码只补上了未命中时的 `ExitProcess(0)`，未在本次环境编译执行。文章称该检查在微步与安恒云沙箱上均使样本“无法正常运行”，但未展示进程枚举返回值与退出路径的截图。

## 变体与关联

- **白名单类型**：浏览器、Office、企业 IM、输入法、安全软件等；也可用“进程数量 < N”这类粗粒度阈值。
- **组合检测**：与父进程校验、桌面文件数、uptime、用户名/主机名等组合，见 [[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]、[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]。
- **反向用法**：检测特定安全软件进程是否存在（如 `360tray.exe`）后改变行为/退出，见 [[code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum]]。
- **沙箱对抗**：分析平台可在镜像中预置并运行常见软件、随机制造进程列表；仅靠白名单缺失判定会被绕过。

## 检测与防御

- **沙箱侧**：在分析镜像中预置并常驻 QQ/微信/钉钉/企业 IM 等常见软件，或随机生成可信进程列表；对“早期枚举进程后立即退出”的样本延长观察、多环境重复投放。
- **EDR/行为检测**：监控样本启动后短时间内 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + 字符串比较 + 立即退出的组合，以及随后无外联/无落地就结束的模式。
- **防御**：限制未知样本执行；对进程枚举本身不必一律拦截（正常软件也常用），应结合退出时机与后续行为判定。
- **攻击者边界**：白名单越贴近目标用户越准，但误杀也越高；沙箱预置软件后该检查失效。
