---
id: code-analysis-reverse-obfuscation-php-eval-gzinflate-echo-unwrap
title: PHP eval(gzinflate(base64_decode())) 外壳动态还原：eval 改 echo + ob_start 递归剥壳
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: php-eval-gzinflate-base64-dynamic-echo-unwrap
tags:
- php
- obfuscation
- eval
- gzinflate
- base64
- deobfuscation
- webshell
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V293
  verified_at: '2026-11-08T08:09:25+08:00'
  notes: 已对照原文及图 13-15 核对：enc.php 为 <?php /*Protected by Al1ex*/ eval(gzinflate(base64_decode('4+UqyCjIzEvL19C0VrC3AwA='))); ?>，原文反解用 eval 改 echo + ob_start/ob_get_clean、300 层上限、strpos 检查 eval(gzinflate(base64_decode、htmlspecialchars 输出，与卡片 PoC 一致。dup-scan/dedup 将本卡与同篇 chr-shift-custom-decoder 判 likely_duplicate（cosine 0.92），经对照两者为同一外壳族的不同原子：本卡直写 gzinflate(base64_decode) 的通用动态剥壳，另一卡是自定义 sou() 解码函数+逐字节 ASCII 偏移变种，触发与还原步骤不同且互相引用，判为并列保留；与既有 php-gzinflate-strtr-base64-unwrap 也为静态 Python 复现 vs 动态 echo 的不同方法，保留。未验证点：未在本机运行 PHP/PoC；原文用 Web 环境（PHP 5.3.29）演示，卡片建议 CLI 隔离执行属安全实践差异。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-php-eval-gzinflate-echo-unwrap/
draft: false
kb_aliases:
- PHP eval 壳反解
- eval 改 echo
- gzinflate base64 eval 解密
- PHP 加密马还原
- decodephp 递归剥壳
---

## 一句话结论

对 `eval(gzinflate(base64_decode('...')))` 这类自解压 PHP 外壳，把 `eval` 替换成 `echo` 并用 `ob_start()/ob_get_clean()` 捕获输出，就能让原来的解码表达式照常求值、但把解出的源码打印出来；循环处理嵌套层直到不再出现 eval，即可用十几行 PHP 还原任意层壳。

## 原理

- **eval 是被动执行点**：`eval($expr)` 先求值 `$expr`，再把结果当 PHP 代码执行。把 `eval` 改成 `echo` 后求值行为不变，只是把结果输出，因此外壳自带的解码函数仍会执行，最终明文字符串被打印。
- **gzinflate + base64_decode 是纯函数**：`base64_decode` 把 base64 文本还原为 raw deflate 流，`gzinflate` 解压；两者不依赖外部密钥，参数就在文件中，所以任何能运行 PHP 的环境都能还原。
- **捕获而非直接输出**：`ob_start()` 打开输出缓冲，`eval(...)`/`echo` 的结果被 `ob_get_clean()` 取回，作为下一层输入；这样不会把中间结果混进响应。
- **防止二次解析**：解出的内容通常含 `<?php`/`?>`，直接 echo 给浏览器会被当前 PHP 解析执行；必须用 `htmlspecialchars` 或写文件后再看，避免还原过程触发样本代码。
- **递归上限**：多层嵌套时每轮检查结果里是否仍含 `eval(gzinflate(base64_decode`，含则继续；设 300 层上限防止异常样本死循环。
- **为什么常见**：这类壳无需扩展、只需 PHP 本身即可运行，常被用于 PHP 后门/大马的免杀与源码保护；动态 echo 法与离线静态解码（Python 的 `base64.b64decode` + `zlib.decompress(...,-15)`）等价，但动态法不需要自己识别每一层的编码函数。

## 触发条件

- 拿到可疑 PHP 文件，内容以 `eval(gzinflate(base64_decode('...')))` 或等价的自定义函数调用起头，文件可读但无可读源码。
- 分析环境有 PHP CLI，且样本已复制到隔离目录；不要在 Web 根目录或生产环境直接运行。
- 样本只使用内置的 base64/gzip 函数；若解码逻辑被换成自定义函数或异或密钥，需要先读懂函数（见变体）。

## 利用步骤

1. **确认外壳**：搜索 `eval`、`gzinflate`、`base64_decode`、`gzuncompress`、`gzdecode`，确认调用嵌套关系。
2. **取 eval 语句**：把 `eval(...)` 整句（含参数）单独存成字符串，或用脚本从文件中正则提取；不要把整份 `<?php ... ?>` 直接塞进 eval。
3. **替换并捕获**：对该字符串做 `str_replace('eval','echo',...)`，外层包 `ob_start()` / `ob_get_clean()`，执行一次。
4. **判断是否到底**：输出中若仍有 `eval(gzinflate(base64_decode`，把输出作为下一轮输入继续；否则转义输出即为源码。
5. **审读源码**：检查 `eval`、`assert`、`system`、`file_put_contents`、`$_POST`/`$_GET`、`ignore_user_abort` 等后门特征。
6. **留证**：保存样本哈希、每层解码结果与时间线；不要在样本原目录执行。

## PoC

```php
<?php
// 仅用于隔离环境中的离线副本；$code 为从样本中摘出的 eval(...) 语句
function unwrap_eval_layer($code, $max = 300) {
    for ($i = 0; $i < $max; $i++) {
        ob_start();
        eval(str_replace('eval', 'echo', $code));
        $code = ob_get_clean();
        if (strpos($code, 'eval(gzinflate(base64_decode') === false) {
            return $code;
        }
    }
    return $code;
}

$stmt = "eval(gzinflate(base64_decode('4+UqyCjIzEvL19C0VrC3AwA=')));"; // 示例
echo htmlspecialchars(unwrap_eval_layer($stmt));
```

静态等价物（不执行样本，Python）：

```python
import base64, zlib
raw = base64.b64decode("4+UqyCjIzEvL19C0VrC3AwA=")
print(zlib.decompress(raw, -15).decode("utf-8", "replace"))
```

## 变体与关联

- **gzuncompress / gzdecode**：分别对应 zlib 头和 gzip 头，Python 用 `zlib.decompress(data)` 或 `zlib.decompress(data, 16+MAX_WBITS)`。
- **str_rot13 串联**：先 `str_rot13` 再 base64/gzinflate，按调用顺序逐层反向即可。
- **自定义解码函数 + 字节偏移**：如 `sou()` 中先 `gzinflate(base64_decode())` 再逐字节 `chr(ord()-1)`，需要先读函数体确认偏移方向与步长；见关联卡片。
- **静态多层还原**：若不想执行任何 PHP，可对每层做“提取参数→Python 复现变换”，适合样本含反调试/回连副作用时。
- **关联卡片**：[[code-analysis-reverse-obfuscation-php-gzinflate-strtr-base64-unwrap]]（同类外壳的静态 Python 还原；本卡差异是让外壳解码器自行执行、只把 eval 换 echo，不需要逐层识别编码函数）；[[code-analysis-reverse-obfuscation-php-eval-chr-shift-custom-decoder]]（ASCII 偏移变种）；[[web-php-rce-webshell-0o0o-nested-obfuscator-random-alphabet]]（同族混淆器的生成/识别侧，其步骤提到 eval 换 echo 但未给出递归脚本）。

## 检测与防御

- **静态特征**：`eval\s*\(\s*gzinflate`、`eval\s*\(\s*base64_decode`、超长 base64 常量、`gzuncompress`/`gzdecode` 与 eval 同现。
- **运行侧**：禁用 `eval`/`assert`（`disable_functions` 只提高门槛）；Web 进程禁止写 Web 根目录；容器只读根文件系统。
- **文件完整性**：监控 Web 目录新增/变更的 PHP 文件，尤其是小体积、无注释、变量名随机、mtime 与上传时间吻合的文件。
- **应急**：先隔离样本并保留哈希，不要在生产执行；解码后排查写入路径、外连地址与计划任务。
