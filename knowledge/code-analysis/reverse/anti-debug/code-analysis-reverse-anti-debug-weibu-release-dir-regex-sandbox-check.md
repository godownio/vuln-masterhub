---
id: code-analysis-reverse-anti-debug-weibu-release-dir-regex-sandbox-check
title: 反沙箱：GetCurrentDirectoryA + regex_match 整串匹配 C:\<单段随机目录> 识别微步沙箱释放路径
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: sandbox-release-working-directory-regex
aliases:
- 微步沙箱反检测
- ThreatBook 沙箱识别
- 工作目录正则反沙箱
- C:\随机目录 沙箱指纹
- 反沙箱杂谈
tags:
- anti-sandbox
- evasion
- windows
- malware
- working-directory
- threatbook
- cpp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V444
  verified_at: '2026-11-09T23:02:13+08:00'
  notes: 已对照原文核对：GetCurrentDirectoryA + std::regex_match("^C:\[A-Za-z0-9_]+") 整串匹配 C:\<单段随机目录>、命中判沙箱/弹 Fail 均与原文代码和图片一致（图 01 进程路径 C:\9632fl4\test_weibu.exe，图 02 Fail 弹窗）；regex_match 整串语义说明正确。无 CVE/版本，不涉组件。per-card dedup 仅 related（路径陷阱/进程白名单/域检查等不同维度），不重复。dup-scan.json(11-08) 早于建卡(11-09)。
---

## 一句话结论

微步在线沙箱多年来把样本释放到 `C:\<随机字符串>\` 目录运行（如 `C:\9632fl4\test_weibu.exe`），样本用 `GetCurrentDirectoryA` 取当前工作目录、再用 `std::regex_match("^C:\\\\[A-Za-z0-9_]+")` 整串匹配“根目录下恰好一段字母数字下划线”的路径；命中即判定处于微步沙箱，放弃恶意行为并退出/提示失败。

## 原理

- 微步（ThreatBook）云沙箱释放样本时会创建 `C:\` 下一个随机字符串目录并在其中运行，进程工作目录因此形如 `C:\9632fl4`。这一释放习惯长期稳定，是该沙箱的强指纹。
- 正常用户的程序通常从多段路径启动（`C:\Users\<user>\Desktop`、`C:\Program Files\...`、`D:\downloads\...`），极少直接把可执行文件放在 `C:\` 下单段随机目录里运行。
- `GetCurrentDirectoryA` 返回进程当前目录。`std::regex_match` 要求**整个字符串**与模式匹配（不同于 `regex_search` 的部分匹配），因此模式 `^C:\\[A-Za-z0-9_]+` 即使不带 `$`，在 `regex_match` 语义下也等价于“整串必须恰好是 `C:\` 加一段由字母/数字/下划线组成的名字”。`C:\Users\admin` 因含有第二段反斜杠不会命中，`C:\Windows` 也不会命中，避免了大范围误报。
- 命中时函数返回 false（判定为分析环境），调用方据此跳过解密、注入、外联等敏感动作，甚至弹出 `Fail` 提示，使动态沙箱记录不到恶意行为。
- 该检查的隐蔽性在于：只是读取当前目录后做一次字符串正则匹配，不调用 `IsDebuggerPresent`、不枚举进程、不查询虚拟机工件，属于低敏感 API 行为。

## 触发条件

- Windows 目标，样本以 C/C++ 编写并使用 `std::regex`；
- 样本被投递到微步等把文件释放到 `C:\<单段>` 目录的在线沙箱；
- 检查位于解密/注入/外联等敏感逻辑之前，且前置执行条件（如反调试）不会先失败；
- 真实用户路径通常为多段目录，不触发误杀；若用户恰好从 `C:\tools` 之类的根下单段目录运行，会被误判。

## 利用步骤

1. 在恶意代码入口最前面调用工作目录检查，先于任何可疑行为。
2. `GetCurrentDirectoryA(256, buf)` 取出当前工作目录。
3. 用 `std::regex_match` 整串匹配 `^C:\\[A-Za-z0-9_]+`。
4. 命中则视为沙箱：走无害分支或直接退出（原文效果为沙箱内弹出 Fail）；不命中才进入真正的载荷逻辑。

## PoC

```cpp
#include <windows.h>
#include <string>
#include <regex>

std::string workingdir() {
    char buf[256];
    GetCurrentDirectoryA(256, buf);
    return std::string(buf);
}

bool check_run_path() {
    std::string test(workingdir());
    std::regex pattern("^C:\\\\[A-Za-z0-9_]+");
    if (std::regex_match(test, pattern)) {
        return false;   // 命中微步释放目录形态，判定沙箱
    }
    return true;
}
```

调用方在 `check_run_path()` 返回 false 时退出或执行无害逻辑即可。原文截图中沙箱进程路径为 `C:\9632fl4\test_weibu.exe`，样本最终在微步桌面弹出 `Fail`。

## 变体与关联

- 变体：把正则换成 `^[A-Z]:\\[A-Za-z0-9_]{5,10}$` 之类，可覆盖其他“根目录单段随机名”的释放型沙箱。
- 变体：可结合目录段数、路径是否包含 `Users`/`Program Files` 等白名单做双向判断，降低真实用户误报。
- 注意 `regex_match` 与 `regex_search` 语义不同：若误用 `regex_search`，`C:\Users\...` 也会命中，造成大面积误杀。
- 关联：既有「反沙箱路径陷阱：GetCurrentDirectoryW 仅在盘符根目录返回尾随反斜杠」卡关注的是路径拼接失败的隐蔽门控，本卡关注的是目录名正则指纹；「Windows 免杀沙箱指纹组合检测」等卡覆盖资源/注册表/父进程等其它维度。

## 检测与防御

- 检测：静态扫描样本中的 `GetCurrentDirectoryA/W` + `std::regex` 常量（尤其是 `^C:\\[A-Za-z0-9_]+` 形态）；动态监控入口即读取当前目录并做字符串匹配、随后立即退出或弹窗的样本；对“入口后很快退出且无网络/文件行为”的样本换释放目录重放。
- 防御/分析侧：沙箱把释放目录改为多段用户目录（如 `C:\Users\Public\Documents\<random>`），或对 `GetCurrentDirectoryA` 返回值做 hook/伪装；多目录重放以绕过单点路径判断。
- 样本侧取舍：路径检查会误杀从根下单段目录运行的真实用户，且该指纹依赖沙箱实现稳定；一旦沙箱改为随机多段路径即失效。
