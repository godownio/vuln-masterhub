---
id: defense-forensics-brc4-badger-config-json-beacon-format
title: BRC4 Badger C2 配置与请求格式：管道分隔域名/端口/UA + JSON cds/mtdt 加密 POST
type: scenario
domain: defense
path: defense/forensics
technique: brc4-badger-pipe-config-json-beacon-format
aliases:
- Brute Ratel Badger 配置
- BRC4 C2 配置提取
- kurvabbr.pw
- barsen.monster
- 7444 端口
- cds auth mtdt
- bookmarks.php work.php
tags:
- windows
- forensics
- c2
- brc4
- badger
- config-extraction
- beacon
- ioc
- json
- wininet
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V306
  verified_at: '2026-11-08T11:57:31+08:00'
  notes: 已对照原文与 img21-31 核对：管道配置 |0|60|40|100|...|kurvabbr.pw,kurvabbr.pw,barsen.monster|7444|Chrome/126 UA|...|bookmarks.php,/work.php、JSON {"cds":{"auth":"TFSM6PP82UGOT5N"},"mtdt":...}、GetComputerNameW/GetComputerNameExW/GetUserNameW/GetTokenInformation、WinINet 连接 kurvabbr.pw:7444 /work.php、密文 e081ee9e...、IOC（域名/IP/URL/SHA256）均与截图一致；加密算法/key 原文未给出；未复跑样本
---

## 一句话结论

BRC4 Badger 在内存中解密出的配置是管道分隔字符串，其中含 C2 域名列表 `kurvabbr.pw,kurvabbr.pw,barsen.monster`、端口 `7444`、Chrome/126 的 User-Agent 与 URL 后缀 `bookmarks.php,/work.php`；样本用 `GetComputerNameW/GetComputerNameExW/GetUserNameW/GetTokenInformation` 收集主机信息，拼成 `{"cds":{"auth":"TFSM6PP82UGOT5N"},"mtdt":{"h_name":...,"wver":...,"ip":...,"arch":"x64","bld":...,"p_name":...,"uid":...,"pidv":...}}`，加密后通过 WinINet（`InternetConnectW`/`HttpOpenRequestW`/`InternetSetOptionW`）POST 到 `https://<domain>:7444/<suffix>`。

## 原理

- **配置形态**：Badger 把配置以 `|` 分隔的字符串保存在内存/载荷中；截图寄存器可见 `|0|60|40|100|||||||||||||0|1|kurvabbr.pw,kurvabbr.pw,barsen.monster|7444|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36|...|bookmarks.php,/work.php|...`。域名列表用逗号分隔，同一域名重复出现可用于轮询/容错；端口 7444；URL 后缀 `bookmarks.php` 与 `/work.php` 对应不同 URI 模板。
- **配置提取**：在样本内存中搜索域名、端口、UA 或 `|0|60|40|100|` 特征，即可定位配置块；字段含义原文未逐一说明（前段 0/60/40/100 可能是 sleep/jitter/超时等参数，需结合样本版本确认）。
- **主机指纹**：样本调用 `GetComputerNameW`/`GetComputerNameExW` 取主机名，`GetUserNameW` 取用户名，`GetTokenInformation` 取令牌/权限信息；随后把主机名、Windows 版本、IP、架构（x64）、构建号、进程名、用户 ID、进程 ID 等填入 `mtdt`。
- **请求 JSON**：内存中出现 `{"cds":{"auth":"TFSM6PP82UGOT5N"},"mtdt":{"h_name":"...","wver":"...","ip":"...","arch":"x64","bld":"...","p_name":"...","uid":"...","pidv":"..."}}`。`cds.auth` 是会话/认证标识，`mtdt` 是主机元数据；字段名固定，可作为内存/流量检测特征。
- **加密与发送**：请求 JSON 被加密成十六进制串（截图中寄存器指向 `e081ee9e...` 的长串）；随后通过 WinINet API 建立 HTTPS 连接并发 POST。原文未给出加密算法与 key，因此只能提取密文与端点，无法离线解出完整请求。
- **基础设施/IOC**：威胁情报表给出域名 `kurvabbr.pw`、`barsen.monster`，IP `85.208.108.63`，URL `hxxp://85.208.108.63/BST.msi`、`hxxps://barsen.monster:7444/work.php`、`hxxps://kurvabbr.pw:7444/bookmarks.php`，以及多行 SHA256。域名/端口/URI 组合比单一 IP 更稳定，适合作为检测与狩猎条件。

## 触发条件

- 已获得 BRC4 Badger 样本、内存 dump 或流量，且配置已被解密/驻留在内存中。
- 能在内存/字符串中搜索域名、端口、UA 或配置分隔特征；或能在调试器中跟踪配置解析函数。
- 有网络流量或主机可出网，能观察 WinINet 请求；若样本未执行到 beacon 阶段，只能做静态配置提取。

## 利用步骤

1. **静态/内存找配置**：对样本或进程 dump 搜索 `kurvabbr.pw`、`barsen.monster`、`7444`、`Chrome/126`、`|0|60|40|100|`、`bookmarks.php`、`work.php`。
2. **解析管道字段**：按 `|` 分割，标记域名列表、端口、UA、URL 后缀等；域名列表按 `,` 再分割。
3. **定位主机指纹代码**：在调试器中给 `GetComputerNameW`、`GetComputerNameExW`、`GetUserNameW`、`GetTokenInformation` 下断，观察返回的主机名/用户名/令牌信息如何写入 JSON。
4. **抓请求 JSON**：在 JSON 拼装完成后、加密前下断，dump `{"cds":...,"mtdt":...}` 明文；记录 `auth` 与字段名。
5. **抓加密/发送**：在 `InternetConnectW`、`HttpOpenRequestW`、`InternetSetOptionW`、`InternetWriteFile`/`HttpSendRequestW` 下断，记录域名、端口、URI、UA 与密文；结合 pcap/代理确认实际请求。
6. **固化 IOC**：域名、IP、端口、URI、UA、SHA256、配置字符串与 JSON 字段；用这些条件做全网狩猎。

## PoC

从内存/样本字符串中定位配置（只读分析）：

```bash
strings -a -el sample_or_dump.bin | grep -Ei 'kurvabbr|barsen|7444|bookmarks\.php|work\.php|\|0\|60\|40\|100'
strings -a sample_or_dump.bin | grep -Ei 'cds|mtdt|h_name|pidv|TFSM6PP82UGOT5N'
```

解析管道配置（字段含义按版本确认，下面是结构示例）：

```python
cfg = "|0|60|40|100|||||||||||||0|1|kurvabbr.pw,kurvabbr.pw,barsen.monster|7444|Mozilla/5.0 ... Chrome/126.0.0.0 Safari/537.36|...|bookmarks.php,/work.php|..."
fields = cfg.split("|")
domains = next((f.split(",") for f in fields if "kurvabbr.pw" in f), [])
port = next((f for f in fields if f.strip().isdigit() and f.strip() == "7444"), None)
suffixes = next((f.split(",") for f in fields if "bookmarks.php" in f), [])
print(domains, port, suffixes)
# ['kurvabbr.pw', 'kurvabbr.pw', 'barsen.monster'] 7444 ['bookmarks.php', '/work.php']
```

请求 JSON 结构（明文，加密前）：

```json
{"cds":{"auth":"TFSM6PP82UGOT5N"},
 "mtdt":{"h_name":"<hostname>","wver":"<windows version>","ip":"<ip>",
         "arch":"x64","bld":"<build>","p_name":"<process>",
         "uid":"<user id>","pidv":"<pid>"}}
```

说明：原文未给出请求加密算法/key，故不提供密文解密 PoC。

## 变体与关联

- **配置字段变体**：不同 BRC4 版本/Profile 的管道字段数量、顺序、端口、URI 后缀可能变化；以域名列表 + 端口 + UA + URI 为锚点，不要只匹配固定偏移。
- **URI 变体**：`bookmarks.php`、`/work.php` 可被替换为其他伪装路径；同一域名可重复出现用于轮询。
- **流量加密**：若拿到样本中的 key/算法，可进一步解密 POST 体；本卡只覆盖配置与请求格式。
- 关联：[[pentest-c2-brc4-badger-embedded-pe-selfinject-loader]]（配置所属 loader）、[[defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt]]、[[defense-forensics-winos4-c2-frame-xor-decrypt]]（同类 C2 配置/流量提取思路）。

## 检测与防御

- **主机检测**：内存/进程 dump 中出现 `kurvabbr.pw`/`barsen.monster`、`|0|60|40|100|`、`cds`/`mtdt`/`h_name`/`pidv`、`bookmarks.php`/`work.php`；`rundll32` 加载 `%AppData%` DLL 后的进程发起 7444 端口 HTTPS。
- **网络检测**：DNS/代理日志中出现上述域名；TLS SNI/端口 7444；UA 为 Chrome/126 但进程不是浏览器；POST 到 `/bookmarks.php`、`/work.php`。
- **防御**：封禁已知域名/IP/端口与 URI 组合；对 `rundll32`/`msiexec` 子进程的出网行为告警；威胁狩猎时用域名 + 端口 + URI + UA 组合而非单一 IP（基础设施可快速更换）。
- **取证注意**：配置与请求体可能只在内存中解密后短暂存在；优先在 JSON 拼装后、加密前下断提取明文，并记录样本版本与偏移。
