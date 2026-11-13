---
id: code-analysis-reverse-anti-debug-companion-xml-gate-msedge-chrome-loader
title: 伴生 XML 文件门控反沙箱：缺 richlist.xml 或读取失败即弹错退出，载荷仅在文件齐全时解密执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: companion-xml-file-gate-anti-sandbox-loader
tags:
- anti-sandbox
- anti-analysis
- evasion
- windows
- xml
- loader
- masquerading
- msedge
- chrome
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V552
  verified_at: '2026-11-11T22:50:02+08:00'
  notes: 已对照原文与35张截图核对：richlist.xml门控（push offset aRichlistXml/test eax/jnz）、失败分支MessageBoxW(L"Failed to load xml file %s",L"DuU1b")、单实例互斥体L"chrome.exe"、CreateEventW(0,0,1,0)/SetThreadpoolWait/WaitForSingleObject均一致；修正XOR密钥为截图实值exkU+@P$bM（原写PSbM）。dedup各候选为路径/进程/命令行MD5等其它反沙箱检查，无同链，保留。未验证点：未运行样本。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-companion-xml-gate-msedge-chrome-loader/
draft: false
kb_aliases:
- XML 伴生文件门控
- 缺 XML 报错退出
- richlist.xml 校验
- Failed to load xml file
- msedge.exe chrome.exe 伪装
- 压缩包双文件门控
---

## 一句话结论

免杀装载器把恶意分支放在"同目录存在 `richlist.xml` 且能成功读取/解析其内容"之后：压缩包内只有 `msedge.exe`/`chrome.exe` 与 1KB 的 `richlist.xml`（一份无害的 Avalonia 风格 XAML 界面布局），单独运行 EXE（没有 XML、或 XML 内容不符）会进入 `Failed to load xml file %s` 的报错分支并退出；只有完整解压、两文件同在时才解密并执行 shellcode。这让只复制单个 EXE 的沙箱/自动查杀拿不到行为。

## 原理

- **门控点**：EXE 的 `main` 里先 `push offset aRichlistXml`（字符串 `richlist.xml`）调用文件读取/解析函数，`test eax/eax` 判断结果；失败则走到 `MessageBoxW`（样例字符串 `Failed to load xml file %s`、标题形如 `DuU1b`）并返回，成功才 `jmp` 进入解密与执行分支。恶意代码路径与"文件在不在"强绑定。
- **为什么能骗过沙箱**：自动沙箱/AV 模拟器通常只拿到被投递的单个 PE（或把样本丢进临时目录改名运行），不会保留压缩包里的伴生文件；此时读取失败，样本表现为"报错退出"的低危程序，动态行为（VirtualAlloc RWX、线程池回调、联网）一个都不出现。反之人工分析/真实用户从 ZIP 解压后双击，两文件齐全，恶意链正常触发。
- **为什么选 XML 和这个名字**：`richlist.xml` 内容是 `<Window><VBox><HBox><Button …/><VBox class="list">` 之类的 UI 布局（示例文本"自定义列表示例"），本身就是某个正常程序的界面资源；既可作为"为什么压缩包里有个 XML"的合理解释（诱饵），又让读取/解析动作显得像正常程序加载界面配置。
- **命名伪装**：EXE 命名为 `msedge.exe`（另一关联样本为 `chrome.exe`），配合浏览器图标和 4MB 级体积，双击时不易被用户警觉；程序内互斥体也用 `chrome.exe` 等名字，进一步伪装成浏览器进程。
- **为什么有效**：检测的两种常见路径——静态特征与单文件动态——都被"缺文件即退出"切断；只有拿到完整投递包、并把伴生文件一起放进工作目录的分析者才能看到后续，提升了分析成本。

## 触发条件

- 样本以压缩包（ZIP 等）投递，内含伪装成浏览器的 EXE + 一个同名目录下的 `richlist.xml`；受害者解压到同一目录后运行 EXE。
- 门控读取的是相对路径/同目录文件；EXE 与 XML 必须保持在一起，改名或分开放置都会导致提前退出。
- 沙箱/查杀引擎只分析单文件或复制到其他目录时，恶意行为不会触发（这正是攻击者要的效果）。
- 分析侧要复现恶意行为，必须把 XML 一并放进 EXE 所在目录。

## 利用步骤

1. 准备一份无害、看起来合理的 XML（例如 UI 布局），保存为 `richlist.xml`，与载荷 EXE 同名目录分发。
2. 在装载器 `main` 开头加入文件读取/解析门控：读取 `richlist.xml`，失败则弹错误框（如 `Failed to load xml file`）并 `return`；成功则继续。
3. 把真正的恶意逻辑（内嵌加密 shellcode 的解密、VirtualAlloc、线程池回调执行）只放在门控成功后的分支；可再加单实例互斥体等常规反分析措施。
4. 将 EXE 命名为 `msedge.exe`/`chrome.exe` 等浏览器名，与 XML 一起打包成 ZIP 投递。
5. 受害者解压运行后，门控通过 → 解密 shellcode → 进入多阶段加载（见关联卡）。

## PoC

门控逻辑示意（C 伪代码，按原文反汇编还原）：

```c
int main(void) {
    if (!load_and_parse_xml(L"richlist.xml")) {          // 失败分支
        MessageBoxW(NULL, L"Failed to load xml file", L"DuU1b", MB_ICONERROR);
        return 0;
    }
    // 成功分支：单实例互斥体 → 解密内嵌 shellcode → 执行
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"chrome.exe");
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(hMutex); return 0; }
    decrypt_and_execute_embedded_stage();
    return 0;
}
```

实测触发差异：把 EXE 单独复制到空目录运行 → 弹 `Failed to load xml file` 并退出；把 `richlist.xml` 放回同目录再运行 → 进入解密执行分支。

## 变体与关联

- **伴生文件类型变体**：除 XML 外，门控文件可换成配置文件、license、图片、DLL 或任意诱饵文档；判定可以是文件存在、内容校验、甚至用文件内容做解密密钥。本卡样本的 XML 只做门控，不参与解密（shellcode 密钥是硬编码的 `exkU+@P$bM` 重复串 XOR）。
- **同类环境依赖反沙箱**：库内另有"反沙箱路径陷阱：GetCurrentDirectoryW 仅在盘符根目录返回尾随反斜杠"卡，同样是"环境不符合就提前退出"的思路，区别是依赖当前路径而非伴生文件。
- **本样本后续链**：门控通过后同样用 XOR（`exkU+@P$bM`）解密多段 shellcode，第一/二段用 `CreateThreadpoolWait` 线程池回调执行（见 CreateThreadpoolWait 卡），第三段经 WinINet `InternetReadFile` 读取远端下一阶段，最终反射加载 Cobalt Strike beacon；关联样本 `chrome.exe`/`123.exe`/ProgramData 压缩包同属一批（2023-08/09，疑似攻防演练红队样本），配置指向腾讯云 API 网关域名（与库内腾讯 apigw C2 卡属同一手法）。
- **命名伪装变体**：`msedge.exe`、`chrome.exe` 之外，也可用 `svchost.exe`、`explorer.exe`、更新器名；配合"必须与 XML 一起运行"可进一步筛选分析环境。

## 检测与防御

- **动态分析侧**：沙箱要保留并一起投放压缩包内的所有伴生文件（XML/配置/DLL），按原始目录结构运行，而不是只取 EXE；对"读取同目录 XML 失败即退出"的样本标记为可疑门控。
- **静态侧**：检索 `Failed to load xml file`、`richlist.xml` 等字符串与"文件读取→条件跳转→MessageBox→return"的小函数模式；伪装成浏览器名但无浏览器版本信息/签名的 PE 提高告警级别。
- **行为侧**：进程读取同目录 XML 后立刻 `VirtualAlloc(PAGE_EXECUTE_READWRITE)` 并调用线程池/回调 API（`CreateThreadpoolWait` 等），是强组合信号；监控非浏览器路径的 `msedge.exe`/`chrome.exe` 进程创建。
- **投递侧**：邮件/IM 网关解包检查"EXE+XML 双文件"结构，尤其是 XML 为 UI 布局而 EXE 为高熵 PE 的组合。

## 备注

- 原文分析两个同族样本（`msedge.exe` 2023-09-11、`chrome.exe` 2023-08-10），均带 `richlist.xml` 且缺文件时报错，可确认门控行为一致。
- 原文未给出 XML 参与解密的证据，故本卡只把 XML 定位为执行门控/诱饵；不排除其他变体用 XML 内容做密钥。
