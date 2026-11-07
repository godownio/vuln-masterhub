---
id: web-generic-auth-xinhu-publicsave-arbitrary-table-write
title: 信呼 OA publicsaveAjax 任意表/字段写入导致垂直与水平越权
type: scenario
domain: web
path: web/generic/auth
technique: public-save-arbitrary-table-field-write
tags:
- web
- php
- xinhu
- oa
- authorization
- idor
- mass-assignment
- arbitrary-write
- database
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T01:55:47+08:00'
  notes: 已对照原文与5张图核对：publicsaveAjax 仅 iszclogin + 表名签名 + 非空表名校验，表名/字段/值/otherfields 全部客户端可控，->record 写入；图02/04 低权限用户(uid=12 奶龙、uid=7 赵子龙)两次调用均返回 success=true(id=5/6)，图03/05 管理员端出现对应手动签到记录，垂直+水平越权成立。数据库后门仅原文推测、卡片已标注未验证；签名校验为前置条件已写明。未执行 PoC；无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-xinhu-publicsave-arbitrary-table-write/
draft: false
kb_aliases:
- 信呼 OA 越权
- publicsaveAjax
- 公共保存接口任意表写入
- 数据库后门
- OA 批量赋值越权
---

## 一句话结论

信呼 OA 的公共保存接口 `publicsaveAjax` 只校验“已登录 + 表名签名”，不校验当前用户是否有权写目标表、目标字段或目标记录；已登录的低权限用户可控制 `tablename_postabc`、`submitfields_postabc`、任意字段值和 `otherfields`，向任意表插入/更新任意数据，实现垂直越权（执行管理员专属操作）、水平越权（修改他人记录），并可进一步植入数据库后门。

## 原理

- `webmain/webmainAction.php` 的 `publicsaveAjax()` 是通用保存入口，入口检查只有：
  - `$this->iszclogin()`：是否登录；
  - `isempt($table)`：表名非空；
  - `checksignature($this->post('tablename_postabc'))`：表名签名校验。
  没有 `role`/`permission` 校验，也没有“当前用户是否能编辑该表/该 `id`/该 `uid`”的对象级授权。
- 表名来自 `tablename_postabc`，先经 `iconvsql`/`xssrepstr` 变换，再 `m($table)` 取模型；字段列表来自 `submitfields_postabc` 的 Base64 解码（`explode(',', ...)`）；每个字段的值来自同名 POST 参数；`otherfields` 还可以追加 `key=value` 形式的任意列，并支持 `{now}`、`{date}`、`{admin}`、`{adminid}`、`{companyid}` 占位符替换。
- 最终 `$db->record($uaarr, $where)` 把攻击者构造的字段/值写入目标表；`$where` 为 `id='$id'`（`id` 强制转 int），所以问题不是 SQL 注入，而是“表、列、记录、操作类型全部由客户端决定”的批量赋值/功能级授权缺失。
- `beforesaveaction`/`aftersaveaction` 参数还允许调用当前控制器中存在的任意方法（`method_exists($this, ...)` + `$this->$action(...)`），为二次利用留出攻击面；`fileid` 可触发附件关联逻辑。
- 垂直越权示例：只有管理员能手动签到，但低权限用户直接调用该接口即可向签到表写入记录；水平越权示例：把 `uid` 改为其他用户 ID，即可替他人写入记录。
- 数据库后门示例（潜在）：向管理员表/用户表/权限表插入或修改字段（如新增管理员、改密码哈希、改权限标志），或向配置表写入恶意数据；具体表名/字段需按目标库结构枚举。文章未给出该后门 PoC，属于基于同一原语的延伸。

## 触发条件

- 目标为信呼 OA（`webmain/webmainAction.php` 可访问），且 `publicsaveAjax` 未做表/字段/记录级授权。
- 攻击者拥有一个已登录的低权限账号（接口要求 `iszclogin()`）。
- 能提供目标表名对应的有效 `sys_signature`/`sys_timeature`（签名校验必须通过；可从合法请求中捕获，或分析前端 JS 的签名生成逻辑）。
- 表名编码/签名与目标版本匹配；目标数据库表/字段结构已知或可枚举。

## 利用步骤

1. 登录低权限账号，获取 Cookie。
2. 从合法前端请求或 JS 中获取目标表的 `tablename_postabc` 编码值与 `sys_signature`/`sys_timeature`。
3. 按路由规则构造：`a=publicsave&m=index&d=&ajaxbool=true`。
4. 构造 `submitfields_postabc`（Base64 编码的逗号分隔字段列表）和对应字段值；用 `otherfields` 追加固定列（如 `type=3,optdt={now}`）。
5. 发送 POST；响应 `{"success":true,"msg":"处理成功","id":...}` 表示写入成功。
6. 垂直越权：向管理员专属表/记录写入；水平越权：修改 `uid`/`id` 指向其他用户。
7. 数据库后门：枚举管理员/权限/配置表，插入或修改对应字段。

## PoC

```http
POST /xinhu-master/index.php?a=publicsave&m=index&d=&ajaxbool=true&rnd=746864 HTTP/1.1
Host: target
Cookie: <低权限用户已登录 Cookie>
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest

id=0&recename=%E5%A5%B6%E9%BE%99&uid=12&dkdt=2025-08-07+10%3A09%3A00&explain=&otherfields=type%3D3%2Coptdt%3D%7Bnow%7D&tablename_postabc=yd0vj0dm0jmd0yd0vm0jje0jjv01&submitfields_postabc=ZGtkdCx1aWQsZXhwbGFpbg%3A%3A&aftersaveaction=&beforesaveaction=&editrecord_postabc=false&sysmodenumabc=&sys_signature=a934e59c687e71ec0526e65df13e1d9f&sys_timeature=1755396567
```

```text
# 响应：
{"success":true,"msg":"处理成功","id":5}
```

```text
# 水平越权：把 uid 改为他人 ID（如 uid=7），其余不变
# 响应 success=true，管理员端可见他人的签到记录。

# 字段说明（原文）：
# submitfields_postabc Base64 解码 = "dkdt,uid,explain"
# tablename_postabc 为应用 iconvsql 编码后的表名
# otherfields 支持 type=3,optdt={now} 等追加列
```

## 变体与关联

- 变体：`beforesaveaction`/`aftersaveaction` 可调用控制器内已有方法；若某方法内部执行危险操作（文件、命令、模板），可能从越权提升为 RCE（需按目标代码审计，文章未验证）。
- 变体：`fileid` 可关联附件；若附件表/路径可控，可能进一步影响文件访问。
- 变体：同类“公共保存接口”在其它 OA/CRM 中也常见：表名、字段名、记录 ID 由客户端提交，服务端只校验登录。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（已登录用户的 IDOR）；[[web-generic-auth-unauth-user-create-admin-takeover]]（用户创建/接管类越权）；`web/generic/auth` 下的权限校验缺陷卡片。
- 边界：签名校验必须通过；若目标版本对表名/字段做白名单、或按当前用户权限过滤可写表/字段/记录，则链路失效。数据库后门部分原文只提出可能性，未给出具体表名与 PoC，置信度低于越权部分。

## 检测与防御

- 检测：审计 `publicsaveAjax` 等通用保存接口是否校验“当前用户可写目标表/字段/记录”；监控同一低权限账号对多张表、多个 `uid` 的批量保存请求；对比前端正常请求与异常请求的 `tablename_postabc`/`submitfields_postabc`/`otherfields`。
- 修复：在服务端按“表 → 字段 → 记录”做对象级授权；表名/字段名使用服务端白名单；禁止客户端通过 `otherfields` 任意追加列；`uid`/`id` 必须校验归属。
- 加固：签名只能证明请求完整性，不能替代授权；对 `beforesaveaction`/`aftersaveaction` 做方法白名单；记录关键表的写入审计日志；最小权限数据库账号。
