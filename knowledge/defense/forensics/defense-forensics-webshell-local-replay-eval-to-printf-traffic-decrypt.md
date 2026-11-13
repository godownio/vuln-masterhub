---
id: defense-forensics-webshell-local-replay-eval-to-printf-traffic-decrypt
title: 加密 WebShell 流量解密：从流量取马源码，本地搭建后把 eval 改为 printf，回放密文请求体直接得明文
type: scenario
domain: defense
path: defense/forensics
technique: webshell-local-replay-eval-to-printf-decrypt
aliases:
- WebShell 回放解密
- 本地复现木马解密流量
- eval 改 printf
- 冰蝎流量回放
- webshell 解密 oracle
tags:
- forensics
- traffic-analysis
- webshell
- behinder
- php
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V651
  verified_at: '2026-11-13T05:03:55+08:00'
  notes: 已对照原文（xz.aliyun.com/news/12489，2023浙江省大学生网络与信息安全决赛-Misc篇 Misc-3 NewGrating）与全部37张图逐张核对：图19 上传请求中 shell.php 源码含 $key="e46023a69f8db309" 与 //DASCTF 注释、未加载 openssl 时 base64_decode+key[i+1&15] 异或、加载时 openssl_decrypt AES128；图20 冰蝎 v3.0 Beta 11 连接本地 PHP 5.6.9 成功；图22/23 显示把 class C 内 eval($p."") 改为 printf($p."")（截图原文，卡内已按截图逐字修正，原稿写的 printf("%s",$p) 保留为更稳妥变体说明）；图24 回放加密 POST 体后响应为 eval(base64_decode('...'))；图25 解码得 cd /www/admin/www.webshell.com_80/wwwroot/upload/ ;ls；图28/29 将流4发送数据拆为4-1轮~4-7轮共7轮；图30/31 FileReverse-Tools 导出 PNG、图32/33 导出 7z，均与卡一致。dedup：top 候选冰蝎 AES-CBC/ECB 解密卡均为'取 key 手写解密器'，本卡为'本地回放+改 sink'，非同一条利用链，dedup_review 成立；dup-scan.json 30 对不涉及本卡。CTF 无组件版本，不设 affected_versions。未验证点：未在本机回放 pcap 复现。
---

## 一句话结论

加密 WebShell 的解密逻辑与密钥都写在马文件里；与其逆向算法手写解密器，不如把流量中拿到的马源码在本地隔离环境跑起来，仅把最后的 `eval($p)` 改成 `printf($p)`/`echo`，再把 pcap 中攻击者发送的加密 POST 体原样回放到本地马，马自身就会把解密后的明文（通常是 `eval(base64_decode('...'))` 嵌套层）打印出来；逐层 Base64 解码即可还原攻击者执行的命令与外带文件，且能自动适配魔改/自定义加密的马。

## 原理

- **马即是解密 oracle**：冰蝎类 PHP 马的请求体处理是 `file_get_contents("php://input") → base64_decode/openssl_decrypt/XOR → explode('|') → call_user_func(new C(), $params) → eval`。解密所需的 key、算法与参数全部在马上；把马原样运行，就等价于拥有一个“输入密文、输出明文”的函数。
- **为什么不手写解密器**：不同版本/魔改马的 key 派生、IV、外层混淆、`|` 分隔与插件封装都可能不同（如 AES-CBC、ECB、RC4+异或、动态 session key）。按马源码复现容易在 padding/偏移上出错；直接执行马代码则无需理解细节。
- **为什么要改 sink**：最终 `eval` 会执行攻击者的 PHP 代码（可能反弹、写文件、触发告警），且被 `@error_reporting(0)` 静默；把 `eval($p."")` 换成 `printf($p."")`（截图原文；更稳妥可写 `printf("%s", $p)` 或 `echo`）后，解密结果只输出不执行，安全地观察明文。
- **为什么能还原全流量**：同一马、同一 key 对历史请求体是确定性的；pcap 中每个客户端 POST 体（Wireshark 里“发送的数据”）按顺序回放即可得到每一轮执行的命令/上传内容。响应体解密则需同样把马的“加密输出”路径改为输出密文明文对照，或用 key 手写反向加密。
- **嵌套层**：冰蝎的 `$params` 本身是插件代码，常见形态为 `eval(base64_decode('...'))`；把 printf 输出再 Base64 解码、必要时重复回放，可继续下钻到命令、文件内容与上传的二进制（PNG/7z 等）。
- **隔离要求**：这等于运行攻击者代码；必须断网/沙箱/一次性容器，禁止挂载生产目录，禁止用生产证书与凭据。

## 触发条件

- 有包含 WebShell 交互的 pcap/HTTP 日志，且能定位到马文件本身（常见于首个上传请求、服务器备份或内存镜像）。
- 本地具备与马匹配的运行环境（PHP + 所需扩展，如 openssl/session）。
- 流量中的请求体完整（HTTP POST 原始 body 未被截断）。
- 可接受在隔离环境中执行攻击者提供的 PHP 代码（仅保留解密逻辑、改掉 sink）。

## 利用步骤

1. Wireshark 追踪 TCP 流，定位上传马的请求，导出马源码（本文例题为冰蝎 3 PHP，`$key="e46023a69f8db309"`，连接密码 DASCTF）。
2. 在一次性容器/断网虚拟机中部署（如 `php -S 127.0.0.1:8080` 或 Apache+PHP），把马放到 web 目录。
3. 将马末尾的 `@call_user_func(new C(),$params);`（或 `eval($p."")`）改为 `printf($p."");`（截图原文），保留其上的 `base64_decode/openssl_decrypt/XOR` 与 key、session 逻辑，保存。
4. 在 Wireshark 中过滤该马的 POST 请求，选择“发送的数据包”，把每个请求体复制出来；用同 Content-Type（通常 `application/x-www-form-urlencoded`）POST 到本地马。
5. 读取 printf 输出的明文；对出现的 `eval(base64_decode('...'))` 逐层 Base64 解码，得到攻击者执行的命令、目录列表与插件代码。
6. 对 `$content` 之类的文件上传字段做两层 Base64 解码，按文件头（PNG `\x89PNG`、7z `7z\xbc\xaf` 等）识别并落盘；多轮请求按时间顺序重复回放，还原完整时间线。
7. 需要解响应体时，把马的输出编码函数改为打印中间值，或用提取到的 key 按马源码手写反向加密。

## PoC

```python
# 1) 本地部署并 patch 马（示例：冰蝎 3 PHP）
#    源码中： class C{public function __invoke($p) {eval($p."");}}
#    改为：   class C{public function __invoke($p) {printf($p."");}}   # 截图原文；也可写 printf("%s", $p)
#    启动：   php -S 127.0.0.1:8080 -t ./shell_dir

# 2) 回放 pcap 中客户端发送的加密 body
import requests, base64

LOCAL = "http://127.0.0.1:8080/shell.php"
bodies = ["<从 Wireshark 复制的第一轮 POST body>", "..."]  # 按时间顺序

for b in bodies:
    r = requests.post(LOCAL, data=b.encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    plain = r.text
    print(plain)                      # 如 eval(base64_decode('...'))
    layer = plain.split("base64_decode('")[1].split("')")[0]
    print(base64.b64decode(layer))    # 命令 / 插件 / 上传内容
```

```text
# 本例还原出的命令：
cd /www/admin/www.webshell.com_80/wwwroot/upload/ ;ls
# 上传文件字段两层 Base64 解码后按文件头识别：
Password.png（PNG 头 \x89PNG）、flag.7z（7z 头 37 7A BC AF 27 1C）
```

## 变体与关联

- 冰蝎 3 默认/魔改版本：AES-128、RC4+异或、动态 key 等都可回放，只要马源码可得；协议细节见 `defense-forensics-behinder-php-webshell-traffic-decrypt`、`defense-forensics-behinder-php-rc4-xor-modified-traffic`、`defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode`。
- 其他家族：哥斯拉/蚁剑的自定义编码器同样可以“本地复现 + 改 sink 回放”；蚁剑编码器特征见 `defense-forensics-antsword-encoder-traffic-decode-features`。
- 只有密文、没有马源码时：只能按 key 手写解密（或从内存/session 提取 key）；使用脚本自身内置算法解密的取证案例见 `ctf-forensics-pcap-http-sm4-webshell-decrypt`。
- 变体：JSP/ASPX 马把 `eval/ClassLoader` 等 sink 改为 `System.out.print`/`Response.Write` 后同样可回放。
- 边界：马依赖外部类/扩展缺失时回放会报错；响应体解密需额外处理；动态 key（每次请求变化）时历史回放可能只对当轮有效。

## 检测与防御

- 取证侧：优先在断网一次性环境执行；保留原始 pcap 哈希与回放记录；回放产物按文件头落盘并计算哈希，避免运行原始 eval。
- 检测侧：流量中出现 Webshell 上传、随后固定 URI 的高频 POST 与加密 body；同一马在多轮请求间 key 不变是回放可行的根因。
- 防御：禁止上传可执行脚本（白名单扩展名、内容检测）；对 Web 目录最小权限、禁用 eval/危险函数；发现马后先镜像取证再清理，避免直接在生产上运行马代码。
