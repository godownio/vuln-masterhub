---
id: defense-forensics-antsword-encoder-traffic-decode-features
title: 蚁剑（AntSword）默认/Base64/chr/RSA 编码器流量还原与检测特征：ini_set 模板、双字符前缀 base64 与响应分段标记
type: scenario
domain: defense
path: defense/forensics
technique: antsword-encoder-traffic-decode-features
aliases:
- 蚁剑流量分析
- AntSword 默认编码器还原
- AntSword base64 编码器解码
- AntSword chr 编码器
- AntSword RSA 流量
- 双字符前缀 base64
tags:
- forensics
- traffic-analysis
- webshell
- antsword
- php
- encoder
- rsa
- detection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T21:33:41+08:00'
  notes: 已对照原文与7张图核对：图01/03 default与base64编码器配置、图02 default请求（1=PHP代码、@ini_set/@set_time_limit模板、r698bc8b603728 双字符前缀base64解出/var/www/html、b2ea8/63f52dd5fe分段标记）、图04 base64请求（1=@eval(@base64_decode(['ied5afd67ff4a5']))、ied5afd67ff4a5代码、v53917dc62eae8辅助参数、3730f213/c6cdcee标记）、图05 chr编码器、图06 RSA配置（客户端私钥+服务端PHP公钥openssl_public_decrypt+ant参数）、图07 RSA请求无@ini_set且响应明文目录列表，均与卡内一致。核对中修正一句话结论中的RSA方向表述：原写'用上传脚本中的公钥加密'，按图06与RSA语义改为'客户端私钥加密、服务端脚本公钥openssl_public_decrypt解密'（knowledge卡，原理段落原本正确）；其余未改。与既有 ctf-forensics-antsword-rot13-reverse-encoder（自定义编码器）、web-php-rce-webshell-rsa-traffic-encoder（RSA实现侧）卡为不同原子，dedup top候选 related/new，非重复。原文未标蚁剑版本，affected_versions 留空正确。未验证点：未用真实pcap复跑还原脚本；chr解码未逐字符实测；RSA PoC的PKCS1_v1_5与PHP openssl_public_decrypt默认填充假设一致但未实测。无 sources/source_url。
---

## 一句话结论

蚁剑（AntSword）PHP 流量的还原取决于所用编码器：default 编码器直接把 PHP 代码放在参数 `1` 里，代码模板包含 `@ini_set("display_errors", "0");` 与 `@set_time_limit(0);`，辅助参数是“2 个随机字符 + base64”的路径；base64 编码器改为 `1=@eval(@base64_decode($_POST['<随机名>']));` 并把代码放进该随机参数；chr 编码器用 `chr()` 串联混淆同一段代码；RSA 编码器则把命令按 `|` 分段、用客户端私钥加密后放进参数 `ant`（服务端脚本内置公钥并用 `openssl_public_decrypt` 解密）。响应侧通过 `asoutput()` 在输出前后拼接分段标记（如 `b2`+`ea8`、`63f52`+`dd5fe`、`3730`+`f213`、`c6c`+`dcee`），可用于切分与识别。

## 原理

- **default 编码器**：请求体为 `1=<PHP 代码>`（URL 编码），代码由 AntSword 生成，负责禁用错误显示、取消超时、处理 open_basedir，并在 `asoutput()` 中用 `ob_start()` 捕获输出、在前后 echo 分段标记。辅助参数名随机（如 `r698bc8b603728`），其值取 `base64_decode(substr(value, 2))`——前 2 个字符是随机混淆前缀，去掉后才是 base64 路径（示例解码为 `/var/www/html`）。
- **base64 编码器**：请求体为 `1=@eval(@base64_decode($_POST['<随机名>']));&<随机名>=<base64 代码>`，外层只负责解码执行，真正代码在随机参数里；同样有“2 字符前缀 + base64”的辅助参数（如 `v53917dc62eae8`）。URL 解码一次即可看到结构，再去掉前缀做 base64 解码。
- **chr 编码器**：把同一段 PHP 代码转成 `chr(N).chr(N)...` 的拼接表达式，请求体形如 `1=@eval(chr(64).chr(105)...);`；还原时按 `chr(N)` 序列转字符即可，属于“换汤不换药”的多层编码。
- **RSA 编码器**：AntSword 的 PHP RSA 编码器会在服务端放一个带公钥的解码脚本（`$cmd=@$_POST["ant"]; $cmds=explode("|",$cmd); openssl_public_decrypt(base64_decode($value), $de, $pk); ... eval($cmd);`）；请求参数为 `ant`，内容是多段 base64 密文用 `|` 分隔。由于只有请求被加密，响应通常仍是明文（示例中响应直接列出目录内容），这是该编码器的已知缺陷。
- **响应分段标记**：`asoutput()` 把输出前后的标记拆成两段 echo（如 `"b2"."ea8"` 与 `"63f52"."dd5fe"`；base64 编码器为 `"3730"."f213"` 与 `"c6c"."dcee"`），因此响应体是“前缀标记 + 业务输出 + 后缀标记”，可用标记切出真实结果。
- **检测特征**：
  - 明文请求包含 `@ini_set("display_errors", "0");` 与 `@set_time_limit(0);`；
  - 编码/加密后的请求不再出现这两个模板；
  - 多参数请求的参数值常为“2 个随机字符 + base64”；
  - User-Agent 为正常浏览器 UA，没有固定关键字，每次请求可能不同，甚至在不同操作系统标识之间切换——这种“不规律”本身可作为异常特征；
  - 部分版本的 UA 可能是 `antsword xxx`（版本差异）；响应内容也可能是编码后的。
- **为什么可还原**：编码器只做编码/加密，不改变协议结构；请求里保留了 eval/解码入口与参数名，响应里保留了分段标记，按编码器逆运算即可还原。

## 触发条件

- 抓取到发往 PHP WebShell 的 HTTP 流量（POST 为主），攻击者使用蚁剑及其默认/内置编码器。
- 流量的请求体未经过 TLS 以外的二次加密（RSA 编码器需要私钥；默认/base64/chr 可直接还原）。
- 分析者知道或能识别编码器类型；响应未被额外编码（否则需同时还原响应编码）。

## 利用步骤

1. 对请求体做一次 URL 解码，观察是否存在 `1=` 参数、`@eval`、`@ini_set`、`chr(`、`openssl_public_decrypt` 等特征。
2. **default**：取参数 `1` 的值即 PHP 代码；辅助参数去掉前 2 字符后 base64 解码得到路径/参数值；响应去掉前后分段标记得到输出。
3. **base64**：从 `1=@eval(@base64_decode($_POST['<name>']))` 提取 `<name>`，对该参数 base64 解码得到 PHP 代码；辅助参数同样去 2 字符前缀再 base64 解码。
4. **chr**：解析 `chr(N)` 序列并转成字符，或用等价的表达式求值（在隔离环境）得到 PHP 代码。
5. **RSA**：取得编码器生成的私钥，对 `ant` 参数按 `|` 分段、逐段 base64 解码后用 `openssl_private_decrypt` 解密；若响应为明文，直接读取。
6. 用响应分段标记/`asoutput` 结构切出命令输出，还原攻击者的目录浏览、文件读写、命令执行会话。

## PoC

识别与还原的最小逻辑（Python 伪代码）：

```python
import base64, re, urllib.parse

body = urllib.parse.unquote(post_body)

# default: 1=<php code>
if re.search(r'(^|&)1=', body) and '@ini_set("display_errors"' in body:
    code = urllib.parse.parse_qs(body)["1"][0]
    print(code)

# base64: 1=@eval(@base64_decode($_POST['name']));&name=<b64>
m = re.search(r"@eval\(@base64_decode\(\$_POST\['([^']+)'\]\)\)", body)
if m:
    params = urllib.parse.parse_qs(body)
    code = base64.b64decode(params[m.group(1)][0]).decode()
    print(code)

# 辅助参数：去掉前 2 个随机字符再 base64
for k, v in urllib.parse.parse_qs(body).items():
    if k != "1" and len(v[0]) > 2:
        try:
            print(k, base64.b64decode(v[0][2:]).decode())
        except Exception:
            pass
```

RSA（有私钥时）：

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

key = RSA.import_key(open("private.pem").read())
cipher = PKCS1_v1_5.new(key)
for block in post_body.split("|"):
    print(cipher.decrypt(base64.b64decode(block), None))
```

## 变体与关联

- **自定义编码器**：ROT13、Reverse（字符倒序）、XOR 等按插件顺序逐层还原，见 [[ctf-forensics-antsword-rot13-reverse-encoder-traffic-decode]]。
- **RSA 编码器实现侧**：公钥解码脚本与 myencoder 配置见 [[web-php-rce-webshell-rsa-traffic-encoder]]。
- **其他 WebShell 管理器**：冰蝎、哥斯拉的流量解密各有固定密钥/协议，见 defense/forensics 下相关卡。
- **边界**：UA 特征随版本变化（`antsword xxx` 只适用于部分版本）；响应若被二次编码需同时还原；RSA 无私钥时只能看到密文，但可凭请求结构识别编码器。

## 检测与防御

- **流量检测**：对 POST 到 `.php` 的请求匹配 `@ini_set("display_errors", "0")` + `@set_time_limit(0)`、`eval(base64_decode($_POST[`、长串 `chr(`、`openssl_public_decrypt`、`ant=` 等特征；关注“2 随机字符 + base64”的参数值与响应中的分段标记。
- **行为检测**：随机浏览器 UA（尤其同一源 IP 在多个 OS UA 间切换）访问同一 PHP 文件的 POST 请求；请求体长度异常、参数名随机化；响应体以固定短标记包裹业务输出。
- **防御**：修复上传/文件写入与 RCE 入口，禁用 `eval`/危险函数；部署 WebShell 检测与文件完整性监控；WAF 规则覆盖上述模板；对已确认的蚁剑会话，按流量时间线排查文件操作与命令执行范围。
