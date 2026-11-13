---
id: web-generic-auth-xinxiang-oa-cookie-existence-login-bypass
title: 新翔OA checklogin 仅判断五个 Cookie 存在且非空：伪造 id/loginname/jueseid/danweiid/quanxian=1 直接进入后台
type: scenario
domain: web
path: web/generic/auth
technique: cookie-presence-only-login-bypass
tags:
- php
- oa
- auth-bypass
- cookie
- logic-flaw
- unauthenticated
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V541
  verified_at: '2026-11-11T19:22:50+08:00'
  notes: '已对照原文与 16 张截图核对：图15 Burp 请求 GET /main.php 携带 Cookie: id=1;loginname=1;jueseid=1;danweiid=1;quanxian=1;（原文第124行命令一致），图16 放行后进入 OA 工作台（工作任务/公文审批/请假审批/备忘录），页面 Notice 显示 /www/admin/.../OAsystem/main.php，证明未登录仅凭 Cookie 存在性进入后台。原文 islogin() 代码（第127-131行）只做 isset + !='''' 判断，卡内代码一致，无签名/会话绑定。修正：卡内『右上角用户 admin』在原图中不可见（浏览器标签为『新翔OA管理系统-OA管理平台』，图15 登录页用户名框为 admin），已改为按截图可见事实描述。dedup：recommendation=new，related 的 unsigned-cookie-admin-keys 等为不同产品/不同 Cookie 校验缺陷，本卡特指五 Cookie 存在性 islogin()，非同一链；全库仅本卡含『新翔』；dup-scan 无本篇 pair。未验证点：未复现；quanxian/jueseid 具体取值对功能权限的影响原文未逐一验证。'
url: /docs/web/generic/auth/web-generic-auth-xinxiang-oa-cookie-existence-login-bypass/
draft: false
kb_aliases:
- 新翔OA 登录绕过
- checklogin.php islogin 绕过
- Cookie 存在性鉴权
- id loginname jueseid danweiid quanxian
- OA 后台未授权访问
---

## 一句话结论

新翔OA 的 `checklogin.php` 中 `islogin()` 只判断 `id`、`loginname`、`jueseid`、`danweiid`、`quanxian` 五个 Cookie 是否存在且非空，完全不校验签名、服务端会话或数据库；攻击者在浏览器中设置 `id=1; loginname=1; jueseid=1; danweiid=1; quanxian=1;` 即可通过鉴权，直接访问 `/main.php` 等后台页面（原文截图成功进入 OA 后台管理平台）。

## 原理

- 鉴权代码：
  ```php
  function islogin(){
     if(isset($_COOKIE['id'])&&isset($_COOKIE['loginname'])&&isset($_COOKIE['jueseid'])
        &&isset($_COOKIE['danweiid'])&&isset($_COOKIE['quanxian'])){
        if($_COOKIE['id']!=''&&$_COOKIE['loginname']!=''&&$_COOKIE['jueseid']!=''
           &&$_COOKIE['danweiid']!=''&&$_COOKIE['quanxian']!=''){
            return true;
        }
     }
     return false;
  }
  ```
  条件只是“存在且非空”，而 Cookie 完全由客户端控制；没有任何 HMAC/加密签名、没有与 `session` 或数据库中的用户记录比对。
- 业务代码普遍写成 `include("checklogin.php"); if(!islogin()){ header("location:../index.php"); }`，一旦 `islogin()` 返回 true 就按“已登录”处理；后续页面再从 `$_COOKIE['id']`/`loginname`/`quanxian` 取值做权限判断，攻击者可以任意指定这些值（例如 `quanxian=1` 表示高权限）。
- 之所以成立：把“客户端是否携带某些键”当作认证凭据，而不是把服务端签发的不可伪造令牌映射到用户；逻辑判断缺少密码学绑定，任意值都能满足。

## 触发条件

- 目标为使用该 `checklogin.php` 逻辑的新翔OA版本（原文未给版本区间）。
- 攻击者可向目标域设置任意 Cookie（浏览器 F12/插件，或用 Burp 直接改请求头）。
- 后台页面只依赖 Cookie 中的 id/loginname/角色字段做展示与权限判断。

## 利用步骤

1. 访问任一后台页面（如 `/main.php`），默认会跳转 `../index.php`。
2. 在请求头中加入：
   ```text
   Cookie: id=1; loginname=1; jueseid=1; danweiid=1; quanxian=1
   ```
3. 重新请求 `/main.php`，页面不再跳转，显示后台管理界面（原文浏览器标签为“新翔OA管理系统-OA管理平台”，放行后进入 OA 工作台：工作任务/公文审批/请假审批/备忘录）。
4. 遍历后台功能（工作台、公文审批、请假审批、通讯录等），必要时调整 `quanxian`/`jueseid` 尝试更高权限。
5. 结合前台 SQL 注入读取真实用户名/角色值，可让页面显示更合理、访问更多功能。

## PoC

```http
GET /main.php HTTP/1.1
Host: target:8888
Cookie: id=1; loginname=1; jueseid=1; danweiid=1; quanxian=1;
User-Agent: Mozilla/5.0
```

响应返回 OA 后台页面（而非 302 到 login/index），即绕过成功。

## 变体与关联

- 变体：若某页面还校验 `quanxian` 的具体数值，可尝试 `0/1/2`、常见角色 ID；`jueseid`/`danweiid` 同理逐个 fuzz。
- 变体：部分页面可能再查数据库校验用户是否存在，可配合 SQL 注入拿到存在的 id/userName 值填入 Cookie。
- 关联：[[web-generic-sqli-xinxiang-oa-missing-checklogin-like-injection]]（同系统未授权 SQL 注入，可取得真实用户数据）；[[web-generic-auth-dotnet-setauthcookie-before-check-useraccount]]、[[web-generic-auth-fe-login-opd-admin-session]]（同为“客户端可控身份字段即认证”的登录绕过）。
- 边界：`islogin()` 改为校验服务端 session/签名 Cookie/JWT、或后台入口统一鉴权后失效。

## 检测与防御

- 检测：请求携带 `id/loginname/jueseid/danweiid/quanxian` 等业务 Cookie 且值与真实登录不符；未经过登录接口直接访问 `/main.php`；多账号共用同一组 `1` 值。
- 检测：代码审计关注 `islogin()` 只做 `isset`/`!= ''` 判断、Cookie 无签名、权限字段直接取自 Cookie。
- 防御：认证改为服务端会话（session id 随机不可伪造）或签名令牌（HMAC/JWT 并验签）；用户身份与权限从服务端存储读取，绝不信任客户端 Cookie 中的 id/角色；后台统一入口鉴权；Cookie 设置 HttpOnly/Secure/SameSite。
