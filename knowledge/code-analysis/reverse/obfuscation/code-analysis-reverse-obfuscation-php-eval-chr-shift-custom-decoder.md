---
id: code-analysis-reverse-obfuscation-php-eval-chr-shift-custom-decoder
title: PHP eval 变种壳还原：自定义解码函数内 gzinflate+base64 后再逐字节 ASCII 偏移
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: php-eval-chr-shift-custom-decoder-unwrap
aliases:
- PHP Eval 变异
- sou 函数解码
- chr(ord()-1) PHP 混淆
- ASCII 偏移 PHP 马
- PHP 自定义解码函数还原
tags:
- php
- obfuscation
- eval
- gzinflate
- base64
- chr
- ascii-shift
- deobfuscation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V293
  verified_at: '2026-11-08T08:09:29+08:00'
  notes: 已对照原文及图 16-19 核对：a.php 中 function sou(){=gzinflate(base64_decode()); for(...) []=chr(ord([])-1); return ;} eval(sou(K8wszMpPL9DUsgEA)); 原文反解改为 echo(sou(K8wszMpPL9DUsgEA)) 后得到 phpinfo();，与卡片 PoC/Python 等价实现（base64 decode→zlib -15→逐字节 -1）一致。dup-scan 将本卡与同篇 echo-unwrap 卡判 likely_duplicate，经对照本卡核心是自定义解码函数识别+ASCII 偏移变种，非通用 eval 壳，判为并列保留不删除；与既有 strtr 静态还原卡变换不同。未验证点：未在本机运行 PHP/PoC；原文未讨论 PHP8 未加引号常量报错，卡片该句为 PHP 版本行为补充。
---

## 一句话结论

变种 eval 壳不直接写 `gzinflate(base64_decode(...))`，而是把解码逻辑封装进自定义函数（如 `sou()`），在解压+base64 解码后再对每个字节做 `chr(ord($c)-1)` 之类的固定偏移；还原时先读出函数的偏移方向与步长，再复制该函数并把调用处的 `eval` 改成 `echo`（或直接调用函数打印），即可得到明文源码。

## 原理

- **编码链**：明文先逐字节加 1（`chr(ord($c)+1)`），再 `gzdeflate` 压缩，最后 `base64_encode`；生成的外壳只保留一个自定义解码函数和 `eval(函数(密文))` 调用。
- **解码链**：函数内先 `gzinflate(base64_decode($s))` 得到偏移后的文本，再用 `for` 循环 `chr(ord($s[$i]) - 1)` 把每个字节减 1，还原明文。
- **为什么可逆**：固定步长的逐字节偏移是双射，函数体里同时给出了偏移符号（+或-）与步长（示例为 1）；压缩/编码也是可逆的，参数全在文件中。
- **识别要点**：自定义函数体内同时出现 `gzinflate`/`gzuncompress`、`base64_decode`、`for` 循环、`ord`/`chr` 和一个固定常量；调用处是 `eval(函数名("..."))`。函数名常被随机化，但函数体结构稳定。
- **与直接 eval 壳的区别**：仅把 `eval` 换 `echo` 后得到的是“偏移后的中间文本”，不是源码；必须让自定义函数完整执行（echo 的是函数返回值，函数内部的偏移逻辑会跑），或手工按函数实现复现。示例中把 `eval(sou(...))` 改成 `echo(sou(...))` 即可。
- **语法细节**：部分样本把 base64 串写成未加引号的常量（如 `sou(K8wsz...)`），在 PHP 5/7 会当作字符串并产生 notice，PHP 8 会报错；静态还原时可自行加引号。

## 触发条件

- 可疑 PHP 文件只含一个短小的自定义函数与一行 `eval(函数(...))`，密文是短 base64 串，没有明显 `gzinflate(base64_decode('...'))` 直写形式。
- 能读到函数体，偏移方向/步长为固定常量（若步长或密钥来自外部输入，需要额外条件）。
- 分析环境有 PHP CLI，且样本已隔离；不要在生产执行。

## 利用步骤

1. **提取函数体**：把自定义函数（如 `sou`）完整抄出，确认参数是密文字符串。
2. **读解码顺序**：记录 `base64_decode` → `gzinflate` → 逐字节 `chr(ord(...) ± N)` 的顺序与 N 的符号/大小；顺序不能颠倒。
3. **动态还原**：复制函数到独立脚本，把 `eval(函数(密文))` 改成 `echo htmlspecialchars(函数(密文))`，执行后得到明文。
4. **静态还原**：用 Python 复现：`zlib.decompress(base64.b64decode(s), -15)`，再对每个字节做 `(b ± N) & 0xff`。
5. **多层处理**：若还原结果仍含 `eval(`，把结果作为下一层输入重复；直到出现可读 PHP。
6. **审读**：检查后门写入、命令执行、外连与口令校验逻辑。

## PoC

```php
<?php
// 从样本抄出的解码函数；仅把最后的 eval 调用改为 echo
function sou($tmt) {
    $tmt = gzinflate(base64_decode($tmt));
    for ($i = 0; $i < strlen($tmt); $i++) {
        $tmt[$i] = chr(ord($tmt[$i]) - 1);
    }
    return $tmt;
}
echo htmlspecialchars(sou('K8wszMpPL9DUsgEA')); // 密文替换为样本中的值
```

Python 等价：

```python
import base64, zlib
s = "K8wszMpPL9DUsgEA"
raw = bytearray(zlib.decompress(base64.b64decode(s), -15))
plain = bytes((b - 1) & 0xff for b in raw)
print(plain.decode("utf-8", "replace"))
```

## 变体与关联

- **偏移量为其他值**：`chr(ord()+5)`、`chr(ord()^0x23)` 等同理，按函数体常量调整；异或变体需要提取 key。
- **函数内先偏移后解压**：若顺序是 `chr` 循环在 `gzinflate` 之前，则先逆偏移再解压，不能照抄示例顺序。
- **多层套娃**：每层可能是不同的自定义函数，逐层读函数体、逐层还原。
- **关联卡片**：[[code-analysis-reverse-obfuscation-php-eval-gzinflate-echo-unwrap]]（标准 eval+gzinflate 壳的动态剥壳）；[[code-analysis-reverse-obfuscation-php-gzinflate-strtr-base64-unwrap]]（strtr 字符表内层静态还原）；[[web-php-rce-webshell-0o0o-nested-obfuscator-random-alphabet]]（双字母表 strtr 前缀的另一类外壳）。

## 检测与防御

- **静态特征**：短 PHP 文件内自定义函数同时含 `gzinflate`/`gzuncompress` + `base64_decode` + `chr(ord(`；调用处 `eval(` 直接包函数名。
- **行为特征**：Web 进程执行 `eval` 且参数来自文件内常量；可结合 PHP 审计日志/RASP 观察。
- **防御**：禁用 `eval`/`assert`、限制 Web 目录写权限、文件完整性监控；应急时先隔离样本再还原。
