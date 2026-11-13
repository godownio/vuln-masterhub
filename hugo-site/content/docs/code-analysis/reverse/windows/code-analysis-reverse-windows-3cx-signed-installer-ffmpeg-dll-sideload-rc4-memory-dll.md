---
id: code-analysis-reverse-windows-3cx-signed-installer-ffmpeg-dll-sideload-rc4-memory-dll
title: 3CX 供应链攻击：签名安装包侧加载恶意 ffmpeg.dll，内存定位 FEEDFACE 特征 + RC4 解出内嵌 DLL 的 shellcode 并调 DllGetClassObject 执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: signed-installer-dll-sideload-rc4-embedded-dll-shellcode
affected_versions: Windows 18.12.407、18.12.416；macOS 18.11.1213、18.12.402、18.12.407、18.12.416
tags:
- windows
- dll-sideload
- supply-chain
- signed-installer
- rc4
- shellcode
- in-memory-dll
- malware-analysis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V548
  verified_at: '2026-11-11T22:03:04+08:00'
  notes: 已对照原文（xz.aliyun.com/news/13089）与全部24张图核对：图01 流程图明确 Windows 18.12.407/18.12.416、Mac 18.11.1213/18.12.402/18.12.407/18.12.416；图02/05 数字签名 3CX Ltd/DigiCert Timestamp 2023-03-13；图03 Msiexec 拉起 3CXDesktopApp 进程树；图04 安装目录 3CXDesktopApp.exe(145,770KB)、d3dcompiler_47.dll(5,048KB)、ffmpeg.dll(2,749KB)；图06 进程加载 FFMPEG.DLL；图07 ffmpeg.dll PE 时间戳 2022-11-12 12:12:14；图08-09 CreateFileW/GetFileSize/ReadFile 读取 d3dcompiler_47.dll；图10 FE ED FA CE(FEEDFACE) 定位循环与 12 字节 RC4 密钥表；图11-12 解密后缓冲区出现 4D 5A 90(MZ) 内嵌 PE；图13 x64dbg 跳转 shellcode；图14-15 DllGetClassObject(MultiByteToWideChar/LocalAlloc/CreateThread)；图16 604800 秒(7天)休眠；图17 VT 提交时间线；图18-24 图标尾部 C2 链略。卡片技术点、RC4 密钥 3jB(2bsG#@c7、FEEDFACE、DllGetClassObject、affected_versions 与原文完全一致；已按原文明确版本 set-versions（Windows 18.12.407、18.12.416；macOS 18.11.1213、18.12.402、18.12.407、18.12.416）。dedup：与 whiteblack XOR 卡为一般白加黑 vs 官方供应链投毒实例，不同链；库内无其他 3CX/FEEDFACE 卡。未验证点：未运行样本、未离线 RC4 解密复现；图07 未直接显示“无签名”属性（原文文字断言）；frontmatter 无 sources/source_url（全库惯例）。卡片未修改。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-3cx-signed-installer-ffmpeg-dll-sideload-rc4-memory-dll/
draft: false
kb_aliases:
- 3CX 供应链攻击
- 3CXDesktopApp 后门
- ffmpeg.dll 侧加载
- d3dcompiler_47.dll 加密载荷
- FEEDFACE 特征定位
- RC4 shellcode loader
- DllGetClassObject 内存加载
---

## 一句话结论

被投毒的 3CXDesktopApp 官方签名安装包释放出**合法签名的宿主 EXE（白）+ 恶意 `ffmpeg.dll`（黑）+ 加密的 `d3dcompiler_47.dll`（密文数据）**：宿主按同目录优先加载 `ffmpeg.dll`，后者把 `d3dcompiler_47.dll` 整文件读入内存，按特征码定位后以硬编码 RC4 密钥解出 shellcode；shellcode 内嵌一个 DLL，调用其 `DllGetClassObject` 导出在工作线程里继续执行，全程没有第二个可执行文件落盘，文件层面只看到一个正常签名的电话软件安装包。

## 原理

- **白加黑为什么能过签名校验**：签名只保护被签名的 PE 自身，不约束它运行时从同目录加载哪个 DLL。攻击者保留了 3CX 官方签名的主程序与安装包外壳，只替换/新增 `ffmpeg.dll` 这个正常名字的依赖，终端看到的是一次合法程序的正常 DLL 加载。
- **为什么选 `ffmpeg.dll` 与 `d3dcompiler_47.dll`**：两者都是 Chromium/Electron 应用的常见同目录 DLL，前者本来就是 3CXDesktopApp 会静态加载的模块，后者作为"数据文件"被读取时不会触发模块加载链，且体积可观、便于夹带密文。
- **为什么要做特征码定位 + RC4**：加密后的载荷没有 PE 头等静态特征，只有解密后才在内存里成形；`ffmpeg.dll` 先读入整个 `d3dcompiler_47.dll`，在内存里找特征码（正文描述为 FEEDFACE，对应 MZ/PE 头区域的固定字节序列）确定密文起点，再用内置 RC4 密钥（`3jB(2bsG#@c7`）解密出 shellcode。RC4 实现短小、无库依赖，适合塞进 loader。
- **为什么 shellcode 里再包一个 DLL**：shellcode 负责与架构/位置无关的自举，真正的插件 DLL 通过导出函数 `DllGetClassObject` 被调用；`DllGetClassObject` 是 COM 组件标准导出，`CreateThread` 起线程后由该线程执行后续逻辑，调用链看起来像正常 COM 组件激活，利于绕过只盯 `LoadLibrary`/`CreateProcess` 的行为规则。
- **长休眠的作用**：内嵌 DLL 启动后先休眠约 7 天再外联，规避"样本提交沙箱后只跑几分钟"的动态分析窗口，同时错开供应链事件曝光时间。
- **供应链投毒与木马化的区别**：本例不是攻击者伪造安装包，而是官方构建/分发链路被入侵后签出的"正版恶意包"，因此基于发布者签名的信任与基于下载源的供应链校验都会失效，检测只能落到运行时的同目录 DLL 加载与父进程行为。

## 触发条件

- 用户安装并运行被投毒版本的 3CXDesktopApp（原文明确受影响版本：Windows 18.12.407、18.12.416；macOS 18.11.1213、18.12.402、18.12.407、18.12.416）。
- 安装目录包含签名宿主 EXE、无签名恶意 `ffmpeg.dll`、携带加密载荷的 `d3dcompiler_47.dll`，且目录可被宿主正常加载。
- 宿主 EXE 以同目录优先方式加载 `ffmpeg.dll`，且不校该 DLL 的签名/哈希（官方程序本身即如此）。
- 恶意 DLL 能读取同目录的 `d3dcompiler_47.dll`，并按内置特征码与密钥完成解密。

## 利用步骤

1. 攻陷软件厂商的构建或分发链，把恶意 `ffmpeg.dll` 与加密后的 `d3dcompiler_47.dll` 打进官方安装包，随正常签名的主程序一起分发；安装后目录布局为：`3CXDesktopApp.exe`、`ffmpeg.dll`、`d3dcompiler_47.dll`（以及正常资源文件）。
2. 用户启动 `3CXDesktopApp.exe`，Windows 加载器按同目录优先加载 `ffmpeg.dll`；恶意代码在 DLL 初始化/导出调用阶段获得执行。
3. `ffmpeg.dll` 打开同目录 `d3dcompiler_47.dll`，`CreateFileW` + `GetFileSize` + `ReadFile` 把整个文件读入内存。
4. 在内存中按特征码定位密文起点，使用硬编码 RC4 密钥解密，得到 shellcode；随后把缓冲区改为可执行并跳入 shellcode。
5. shellcode 在自身数据中定位内嵌 DLL，调用其导出 `DllGetClassObject`；该导出把参数转成宽字符、`LocalAlloc` 出参数缓冲并 `CreateThread` 启动后续逻辑。
6. 后续逻辑先休眠约 7 天，再循环请求 `raw.githubusercontent.com/IconStorages/images/main/icon<N>.ico` 等伪装图标，从图标尾部取加密数据（详见关联卡），解密得到 C2 列表并等待下发下一阶段载荷；文中分析时 C2 已失效，最终 payload 未能取得。

## PoC

```text
# 分析侧最小复现路径（不执行样本，仅静态/受控观察）
1) 解包 MSI/安装包 -> 对比安装目录：签名 EXE + 无签名 ffmpeg.dll + 体积异常的 d3dcompiler_47.dll
2) 用 Process Monitor 过滤 3CXDesktopApp.exe 的 LoadImage/CreateFile：
   可见先加载同目录 ffmpeg.dll，随后 ffmpeg.dll 读取同目录 d3dcompiler_47.dll
3) IDA 打开 ffmpeg.dll：
   - 定位 CreateFileW("d3dcompiler_47.dll") 的调用点 -> 读文件/分配缓冲逻辑
   - 在缓冲区上找特征码比较循环（本例 FEEDFACE 相关字节序列）与 RC4 KSA/PRGA 循环
   - 提取硬编码 RC4 密钥，对 d3dcompiler_47.dll 中定位到的密文段离线解密
4) 对解出的 shellcode 做静态扫描：定位其中内嵌的 MZ/PE，确认跳转目标为 DllGetClassObject
5) 对解出的 DLL 查 CreateThread/InternetOpenUrl/Sleep 逻辑与 IOC（图标 URL、分隔符、AES-GCM 参数）
```

```text
判据：签名 EXE 同目录出现无签名且编译时间明显早于发布时间的 ffmpeg.dll；
ffmpeg.dll 内存在"读同目录某 DLL 全文件 + 特征码循环 + RC4 循环 + 跳转执行"的组合；
shellcode 尾部或数据区包含完整 MZ/PE；执行链末端出现 DllGetClassObject + CreateThread。
```

## 变体与关联

- 关联：[[code-analysis-reverse-windows-whiteblack-dll-export-obfuscation-xor-inmemory-payload]]（同类"白加黑安装包 + 内存第二段"的一般化形态，本卡是官方供应链投毒的实例）、[[code-analysis-reverse-windows-bloodalchemy-loader-aes-fnv-lznt1]]（侧加载 + 加密 shellcode 的另一种密码学组合）、[[code-analysis-reverse-windows-silverfox-mainframe-dll-hpock-png-xor-shellcode]]（同目录数据文件解密执行 shellcode 的家族样本）、[[code-analysis-reverse-windows-icon-tail-aesgcm-c2-deaddrop-long-sleep]]（本链后续的图标隐写 C2 获取阶段）。
- 变体：RC4 可换成 AES/XOR 等；特征码定位可换成 PE 头解析或固定偏移；shellcode 内嵌 DLL 可改为反射式加载或 `RtlDecompressBuffer` 展开；宿主可换成任意 Electron/Chromium 应用的同目录依赖 DLL。
- 边界：宿主若改用绝对路径加载或校验 DLL 签名，侧加载失效；若 `d3dcompiler_47.dll` 被安全产品按"同目录异常 DLL/大体积数据文件"拦截，loader 读不到密文；休眠 7 天策略使短时沙箱观测不到外联，但也会让真实环境的行为告警延迟。

## 检测与防御

- 检测：签名主程序进程加载其安装目录下无签名 DLL；主程序进程读取同目录 `.dll` 文件内容（非 `LoadImage`）后出现内存可执行权限变更/线程创建；样本编译时间与官方发布日期明显不符；外联 `raw.githubusercontent.com` 的 `IconStorages` 类仓库并下载 `.ico`；进程内存在 `FEEDFACE` 特征码比较与 RC4 常量/循环。
- 防御：对安装目录内所有 DLL 做发布者签名/哈希白名单校验，或改用 `SetDefaultDllDirectories`/绝对路径加载；EDS/EDR 对"签名进程 + 同目录无签名 DLL + 读同目录数据文件"组合告警；限制终端直连 GitHub raw 等公共代码托管域名；供应链侧对构建产物做可复现构建与双人复核，发布后监控安装包的哈希与内容漂移。
