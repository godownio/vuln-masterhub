---
id: web-generic-auth-registration-key-host-md5-hardcoded-salt
title: 注册密钥由 HTTP_HOST + 硬编码盐的 MD5 派生：拿到源码即可算出 allkey 绕过邀请注册
type: scenario
domain: web
path: web/generic/auth
technique: registration-key-host-hardcoded-salt-md5
tags:
- web
- php
- auth
- registration
- hardcoded-secret
- md5
- code-audit
- business-logic
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T21:14:15+08:00'
  notes: 已对照原文与7张图核对：reg.php 的 allkey 校验代码（session allkey 优先、否则 md5(md5(HTTP_HOST+盐))）与原文逐字符一致；原文示例 allkey=1a8eed4f3e05c811c6b1c5550102e86f 已用 Python 按 md5(md5('127.0.0.1'+盐)) 复算验证完全吻合。核对中发现卡片 PoC/原理中的盐串漏写一个 W（误作 fC4gT5uU2p7kU8e...），已按原文修正为 fC4gT5uU2pW7kU8eL8dI4nK5xE9uT6iW（knowledge 卡两处），修正后示例值可复现；其余推导、会话分支、触发条件与原文一致。与 cookie 签名伪造/其他 MD5 卡机制不同（本卡为注册邀请密钥可预测），dedup top候选 related/new，非重复。原文未标产品版本，affected_versions 留空正确。未验证点：未在目标实例实际注册；盐修正为本次核对所做变更（staging 草稿仍为旧串）。frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-registration-key-host-md5-hardcoded-salt/
draft: false
kb_aliases:
- allkey 绕过
- 注册密钥可预测
- md5(md5(host+salt))
- 邀请码硬编码盐
- 开放注册绕过
---

## 一句话结论

注册接口的“邀请密钥”校验把 `md5(md5($_SERVER["HTTP_HOST"] . "硬编码盐"))` 当作合法 allkey；盐写死在源码里、输入只有攻击者已知（甚至可通过 Host 头控制）的域名，因此拿到源码或产品包的人都能自行算出密钥，绕过邀请限制批量注册——而注册又是后续头像上传 getshell、存储型 XSS 等漏洞的前置条件。

## 原理

- **校验代码**：

  ```php
  if ($allkey == "") { exit("请传入秘钥"); }
  session_start();
  $cloudallkey = $_SESSION["allkey"];
  $appintkey = md5(md5($_SERVER["HTTP_HOST"] . "fC4gT5uU2pW7kU8eL8dI4nK5xE9uT6iW"));
  if ($allkey != $cloudallkey) {
      if ($allkey == $appintkey) {
          // 通过
      } else {
          exit("秘钥错误");
      }
  }
  ```

- **密钥空间等于公开信息**：`HTTP_HOST` 是请求的 Host 头，攻击者本来就知道目标域名（甚至能自行指定 Host）；「盐」是源码里的固定字符串。两者结合后 `md5(md5(...))` 完全可计算，没有任何服务端私有随机量。
- **为什么不是“猜密钥”**：这是确定性派生而非随机校验；攻击者只需读一遍 `reg.php`（源码泄露、商业产品包、白盒审计）就能算出目标域名对应的 allkey；示例对 `127.0.0.1` 算出的值为 `1a8eed4f3e05c811c6b1c5550102e86f`。
- **会话分支不增加安全性**：`$_SESSION["allkey"]` 只是安装/流程中写入的值，未命中时回落到可预测的 `$appintkey`；攻击者无需会话即可通过。
- **危害取决于后续链路**：注册本身可能只是“多一个账号”，但配合任意文件上传（头像上传 Content-Type 绕过后 getshell）、存储型 XSS（注册 IP 伪造进后台）等漏洞，注册即成为完整攻击链的入口。
- **同产品多部署复用**：盐固定在产品源码中，所有客户部署共用；只要域名已知，密钥即可批量算出，不存在“每个站点不同”的隔离。

## 触发条件

- 目标使用该注册接口与 `allkey` 校验逻辑，且 `$appintkey` 分支可达（未强制会话密钥）。
- 攻击者掌握源码/产品包（白盒审计、泄露、商业源码），或盐已被公开。
- 注册接口对失败次数、频率、来源无额外限制。
- 后续功能（上传、发帖、XSS 等）对注册用户开放，使注册具有实际攻击价值。

## 利用步骤

1. 审计 `reg.php` 等注册入口，定位 `$appintkey = md5(md5($_SERVER["HTTP_HOST"] . "<盐>"));`。
2. 取目标实际 Host（或测试 Host 头是否被直接使用），按相同算法计算 allkey。
3. 向注册接口提交用户名、邮箱、密码与计算出的 allkey，确认返回“注册成功”。
4. 登录后访问需要账号的功能，继续利用上传/XSS/越权等后续漏洞。
5. 若 Host 头可控，可尝试构造 Host 使密钥匹配自身计算结果；若产品源码泄露，直接复算所有目标域名。

## PoC

```python
import hashlib

def appintkey(host: str) -> str:
    salt = "fC4gT5uU2pW7kU8eL8dI4nK5xE9uT6iW"
    return hashlib.md5(hashlib.md5((host + salt).encode()).hexdigest().encode()).hexdigest()

print(appintkey("127.0.0.1"))  # 1a8eed4f3e05c811c6b1c5550102e86f（示例值）
```

```http
POST /api/reg.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

zh=testuser&em=test@example.com&mm=pass123&allkey=<计算值>&yzm=undefined
```

## 变体与关联

- **变体**：单层 `md5(host+salt)`、`sha1`、`md5(salt+host)`；盐换常量但仍是硬编码；密钥写成默认值（如 `allkey=123456`）或由安装脚本写入数据库但默认未改。
- **变体**：邀请码由“时间/序号”生成、可枚举；注册接口把 `X-Forwarded-For` 当 IP 记录，还可伪造来源。
- 关联：[[code-analysis-vuln-discovery-php-upload-condition-precedence-whitelist]]（注册后的上传 getshell）、[[web-generic-xss-h3blog-username-xff-log-stored-xss]]（X-Forwarded-For 入库导致的存储型 XSS）、[[crypto-prng-hardcoded-seed-custom-lcg-admin-password-predict]]（硬编码随机源导致凭据可预测）。
- 边界：服务端把密钥改为每部署随机生成并保存在配置/数据库且不可读时，本绕过不成立；注册若需邮箱验证/人工审核，单靠 allkey 不足以完成攻击。

## 检测与防御

- **代码审计**：搜索注册/邀请码逻辑中的 `md5(`、`sha1(`、`HTTP_HOST`、`REMOTE_ADDR` 与硬编码字符串；确认密钥是否包含服务端私有随机量。
- **修复**：邀请码/注册密钥使用服务端生成的随机值，按部署独立存储（数据库/环境变量），不使用公开输入与硬编码盐派生；限制注册频率与来源；对注册后功能做权限与上传审核。
- **检测信号**：短时间内大量注册成功；注册请求 allkey 相同或呈固定值；Host 头异常；新账号立即调用上传/发帖接口。
