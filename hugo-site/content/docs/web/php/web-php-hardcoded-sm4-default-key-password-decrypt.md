---
id: web-php-hardcoded-sm4-default-key-password-decrypt
title: PHP 源码审计硬编码 SM4 默认密钥：StringUtil::encrypt 的 $key='xiaoyewl' 复用 decrypt() 还原后台口令
type: scenario
domain: web
path: web/php
technique: hardcoded-sm4-key-password-decrypt
tags:
- php
- sm4
- hardcoded-key
- credential
- code-audit
- thinkphp
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V432
  verified_at: '2026-11-09T18:59:29+08:00'
  notes: 已对照原文及 18 张图核对：StringUtil::encrypt($data,$key='xiaoyewl') 默认密钥、LoginController 密文比对、SM4.php encrypt/decrypt(base64/16字节分组)与截图 13-15 一致；PoC 与原文解密代码一致。原文未明确指出密文来自 xiaoyewl_admin 表（仅截图显示该表存在），属小推断，不影响手法。原文未给版本，已 clear。dedup 无同类硬编码 SM4 源码审计卡。
url: /docs/web/php/web-php-hardcoded-sm4-default-key-password-decrypt/
draft: false
kb_aliases:
- 硬编码 SM4 密钥解密密码
- StringUtil::encrypt 默认密钥
- SM4 decrypt 还原后台口令
- 源码审计加密口令
---

## 一句话结论

PHP 应用把用户口令用带默认密钥的 `StringUtil::encrypt($data, $key = 'xiaoyewl')` 做 SM4 加密后存库，密钥硬编码在源码且无随机盐/IV；拿到源码（审计或泄露）并读出数据库密文（如 SQL 注入）后，直接实例化应用自带的 `SM4` 类调用 `decrypt($key, $ciphertext)` 即可还原管理员明文口令。

## 原理

- 登录逻辑：`LoginController` 用 `$where['user_password'] = StringUtil::encrypt($pass)` 把用户输入口令加密后与数据库字段比对，说明该字段是可逆加密而非单向哈希。
- `StringUtil::encrypt($data, $key = 'xiaoyewl')` 的密钥是函数默认参数，业务调用不传 key 时所有记录共用同一个硬编码 key；内部 `new SM4()` 后调用 `$sm4->encrypt($key, $data)`，返回 Base64 密文。
- `SM4.php` 实现了标准结构的 SM4 分组加密：`encrypt()` 做密钥扩展、按 16 字节分组加密后 `base64_encode`；`decrypt()` 先 `base64_decode`、校验长度对齐，再做密钥扩展与分组解密。分组模式没有随机 IV/盐，同一明文每次得到相同密文。
- 为什么可逆：对称加密的密钥固定且随源码可得，密文与 key 一起构成完整解密输入；数据库泄露 + 源码泄露（两个常见条件）即可离线还原全部口令，不需要爆破。
- 原文链路：前台 SQL 注入导出 `xiaoyewl_admin` 表口令密文 → 追踪登录处 `encrypt()` → 发现默认 key `xiaoyewl` → 直接调用 `decrypt()` 得到明文。

## 触发条件

- 目标为 PHP 应用，口令字段使用应用内可逆加密（`encrypt/decrypt` 成对出现）且密钥硬编码/使用默认参数；
- 攻击者能读取数据库中的口令密文（SQL 注入、备份/配置泄露、数据库弱口令等）；
- 能获得对应版本的源码或应用自带 SM4 类（同版本部署、源码泄露、镜像/备份）。

## 利用步骤

1. 通过 SQL 注入等方式读出管理员表的 `user_password` 密文字段（Base64 字符串）。
2. 全局搜索登录/改密逻辑中的 `encrypt(`、`decrypt(`、`new SM4`、`password`，定位加密入口与默认 key（本例 `StringUtil::encrypt($data, $key='xiaoyewl')`）。
3. 阅读 SM4 实现，确认分组大小/模式/输出编码（本例 16 字节分组、Base64 输出、无 IV）。
4. 复用应用自带的 `SM4` 类（或按相同实现复刻），对密文调用 `decrypt($key, $ciphertext)`；如密钥长度与实现不匹配，按该类的密钥扩展逻辑处理。
5. 用还原出的明文登录后台；若同一密文对应多处账号，可批量解密。
6. 若加密函数有多个调用点使用不同 key，逐个核对调用参数，不要默认都用同一个 key。

## PoC

```php
$ssm4  = new SM4();
$key   = "xiaoyewl";                  // 源码中 StringUtil::encrypt 的默认 key
$pass  = $_GET['pass'];               // 从数据库导出的 Base64 密文
echo "明文密码是: " . $ssm4->decrypt($key, $pass);
```

原文即在登录控制器同目录引入 `SM4.php` 后按上述方式解密 SQL 注入得到的口令密文。

## 变体与关联

- 变体：密钥可能写在 config、`.env`、前端 JS 或数据库配置表里，审计时以 encrypt/decrypt 调用链为准。
- 变体：AES/DES 等其它可逆加密同样适用：找算法、模式、key/IV，再用应用代码或等价实现解密。
- 关联：[[web-php-dujiaoka-admin-password-hash-reproduce]]（同为源码硬编码口令处理导致后台口令可复现，但那条是 bcrypt+固定 pepper 的单向哈希替换）。

## 检测与防御

- 开发侧：口令存储改用 `password_hash()`（bcrypt/argon2）等单向算法；确需可逆加密时使用 KMS/环境密钥 + 每用户随机盐/IV，禁止硬编码默认 key。
- 审计侧：将 `encrypt/decrypt` 成对函数、默认参数密钥、固定 IV 列为高危模式；检查是否可被 SQL 注入/备份泄露串联。
- 检测：数据库中口令字段出现固定长度 Base64 密文、相同明文密文一致；代码扫描硬编码 key 与 SM4/AES 常量。
