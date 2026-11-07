---
id: web-generic-auth-error-message-username-enumeration
title: 登录错误文案差异导致用户名枚举（不存在该用户 vs 用户名或密码错误）
type: scenario
domain: web
path: web/generic/auth
technique: error-message-username-enumeration
tags:
- web
- auth
- enumeration
- login
- information-disclosure
- error-message
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:29:58+08:00'
  notes: 已对照原文核对：图6/13代码 count<1 抛'不存在该用户'、密码不符抛'用户名或密码错误'，图14前端弹窗'不存在该用户'，差异回显成立；图15全局login_error_count计数与卡内'不按用户区分'描述一致。未验证点：未本机批量枚举；frontmatter无sources/source_url；该缺陷本身为低危信息泄露，卡内已说明。
url: /docs/web/generic/auth/web-generic-auth-error-message-username-enumeration/
draft: false
kb_aliases:
- 错误文案用户名枚举
- 登录回显差异枚举
- 不存在该用户
- 用户名或密码错误
- differential error message enumeration
- 账号存在性判断
---

## 一句话结论

登录接口在“用户名不存在”时返回“不存在该用户”，在“用户名存在但密码错误”时返回“用户名或密码错误”，两条分支的回显不同；攻击者用任意错误密码批量提交候选用户名，即可根据错误文案区分账号是否存在，为后续定向爆破或社工提供有效账号列表。

## 原理

- 正常认证应先按用户名查询用户，再校验密码。很多实现把这两步写成两个独立的失败分支，并分别抛出不同异常：
  ```java
  long count = userDao.countByExample(example);   // 只按 username 查询
  if (count < 1) {
      throw new TipException("不存在该用户");
  }
  String pwd = MD5encode(username + password);
  criteria.andPasswordEqualTo(pwd);
  List<UserVo> users = userDao.selectByExample(example);
  if (users.size() != 1) {
      throw new TipException("用户名或密码错误");
  }
  ```
- 控制器把异常 message 直接放进响应体返回给前端，前端再以弹窗展示。于是“用户不存在”这一分支在响应中可被外部观察到。
- 用户名是否存在属于服务端状态，攻击者不需要知道密码即可通过错误文案读出这一位信息；每提交一个候选用户名就获得一次“存在/不存在”的判定。
- 文章中的系统还对失败次数做了计数，但缓存键是全局的 `login_error_count`，没有按用户名或会话区分：它既不能阻止攻击者换用户名继续枚举，反而会让少量失败后所有用户一起被锁定。这说明“有失败计数”不等于“防枚举”。

## 触发条件

- 登录、注册、找回密码等接口对“账号不存在”和“凭证错误”返回不同文案、错误码、状态码或响应长度。
- 攻击者能直接访问该接口并批量提交候选用户名。
- 接口未对“同一来源枚举大量不同用户名”做有效限速或验证码。
- 目标账号名可从公开信息、命名规律或其它泄露渠道整理成字典。

## 利用步骤

1. 用两个已知存在的账号和一个明显不存在的账号分别提交错误密码，记录响应文案/错误码/长度，确认存在性差异。
2. 整理候选用户名列表：常见管理员名（admin、administrator、root）、员工姓名/邮箱前缀、从文章作者、评论、API 响应中收集的账号。
3. 对每个候选用户名提交固定错误密码，按响应差异判定是否存在；控制并发和速率，避免触发全局锁定或 WAF。
4. 对判定存在的账号做定向密码爆破或密码喷洒；若系统存在全局失败计数，先确认锁定窗口，再降低速率或在窗口外分批尝试。
5. 将有效用户名与其它漏洞结合，例如默认口令、弱口令、可预测的登录令牌等。

## PoC

```http
POST /admin/login HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrong-password
```

存在时返回包含“用户名或密码错误”的响应；不存在时返回包含“不存在该用户”的响应。脚本按关键字分类即可：

```python
import requests

def exists(user):
    r = requests.post("http://target:8081/admin/login",
                      data={"username": user, "password": "wrong-pass"},
                      timeout=10)
    if "不存在该用户" in r.text:
        return False
    if "用户名或密码错误" in r.text or "登录失败" in r.text:
        return True
    return None  # 被锁定/限速/文案变更，需人工确认
```

## 变体与关联

- 变体：响应长度、HTTP 状态码、业务错误码、跳转地址不同，同样可用于枚举。
- 变体：找回密码/注册接口的“该邮箱已注册”“验证码已发送”差异。
- 变体：大小写、空格、Unicode 归一化处理不同导致的存在性差异。
- 关联：[[web-generic-auth-username-enumeration-timing-lockout]]（时间差与锁定 oracle 枚举，本卡为错误文案差异，二者可互补）。
- 关联：[[web-generic-auth-login-bruteforce-response-payload]]（枚举后定向爆破）。
- 关联：[[web-generic-auth-login-rate-limit-bypass-cookie-xff]]（枚举/爆破时绕过限速）。

## 检测与防御

- 防御：对“用户不存在”和“密码错误”返回完全一致的文案、状态码和响应长度；必要时对不存在用户也执行一次 dummy 哈希，使耗时接近。
- 防御：失败计数按用户名 + 来源 IP/会话维度统计，不要使用全局单键；对不存在用户也做等价计数，避免锁定行为成为 oracle。
- 防御：对登录接口加验证码、限速和风控；监控同一来源在短时间内尝试大量不同用户名。
- 检测：同一 IP/会话对大量不同用户名的登录请求；响应中文案分布出现两类；短时间触发全局锁定。
- 注意：枚举本身只是信息泄露，危害取决于后续能否获得口令；单独存在时通常为低危，但与弱口令、默认口令、可伪造令牌组合后可升级为账号接管。
