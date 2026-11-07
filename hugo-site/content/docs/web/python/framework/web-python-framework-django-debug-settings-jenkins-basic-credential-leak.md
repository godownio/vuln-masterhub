---
id: web-python-framework-django-debug-settings-jenkins-basic-credential-leak
title: Django DEBUG 错误页泄露 settings：JENKINS_AUTHORIZATION Basic 凭据与 JENKINS_URL 被读出
type: scenario
domain: web
path: web/python/framework
technique: django-debug-settings-third-party-credential-leak
tags:
- python
- django
- debug
- settings
- information-disclosure
- credential-leak
- jenkins
- basic-auth
- hash-crack
- ssh
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V247
  verified_at: '2026-11-07T12:39:36+08:00'
  notes: 已对照原文核对：/users/ 报错页 Settings 泄露 JENKINS_AUTHORIZATION=Basic YWRtaW46MTE3MjgzNmJkZDdjYzY4NzU1MGU3NTdhNTdkNTdlMjgwNA== 与 JENKINS_URL=http://192.168.66.128:8080；Base64 解码 admin:1172836bdd7cc687550e757a57d57e2804，爆破 P@ssw0rd_123，SSH admin 后私钥登 root，均与正文/截图一致；无版本/CVE。未验证点：未复跑爆破与 SSH 登录；frontmatter 无 sources/source_url。
url: /docs/web/python/framework/web-python-framework-django-debug-settings-jenkins-basic-credential-leak/
draft: false
kb_aliases:
- Django 调试页 settings 泄露
- JENKINS_AUTHORIZATION 泄露
- Django DEBUG 凭据泄露
- /users/ 报错泄露配置
- JENKINS_URL 泄露
- Django settings 第三方凭据
---

## 一句话结论

Django 在 `DEBUG=True` 时访问一个会抛异常的路由（原文 `/users/`）会渲染技术错误页，页面下方的 Settings 区块把整个 `settings` 逐项列出，其中 `JENKINS_AUTHORIZATION='Basic YWRtaW46...'` 与 `JENKINS_URL=('http://192.168.66.128:8080',)` 一并泄露；Base64 解码后得到 `admin:<32 位十六进制哈希>`，对哈希做字典爆破得到明文口令，口令复用到 SSH 登录管理员，再用主机上的 admin 私钥连接 root。

## 原理

- **Django 技术错误页包含 settings**：`DEBUG=True` 时，未捕获异常会触发 `technical_500_response`（或 404 技术页），页面除 traceback、Request Data、Cookies 外，还会展示 `settings` 中每个配置项的名称和值，用于调试；生产环境一旦误开 DEBUG，任何能触发异常的请求都可能变成配置 dump。
- **第三方凭据被放进 settings**：项目把 Jenkins 的访问凭据写成 `JENKINS_AUTHORIZATION='Basic <base64>'`，把内网地址写成 `JENKINS_URL`。Basic 认证只是 Base64 编码，不是加密；解码即得 `admin:1172836bdd7cc687550e757a57d57e2804`。
- **哈希可爆破**：解码后的口令部分是 32 位十六进制串（常见 MD5/哈希格式）；原文用字典爆破得到 `P@ssw0rd_123`。这说明配置里存的是弱口令派生值，而不是不可逆的随机密钥。
- **凭据复用**：爆破出的 `admin:P@ssw0rd_123` 可直接 SSH 登录同一台主机；登录后在 admin 家目录取得私钥，再用该私钥连接 root（root 的 `authorized_keys` 信任同一把 key），完成纵向提权。
- **为什么成立**：错误页的 settings 区块是 Django 调试功能的默认行为，不需要额外漏洞；开发者把第三方系统凭据放在 settings 且使用弱口令，才使“信息泄露”升级为“登录 + 提权”。

## 触发条件

- Django 应用 `DEBUG=True`（常见于测试/预发环境误上生产）。
- 存在能触发未捕获异常的路由（原文为 `/users/`），且异常页未被 Nginx/统一错误页替换。
- `settings` 中存放第三方凭据（如 `JENKINS_AUTHORIZATION`、`JENKINS_URL`）或数据库/SECRET_KEY 等敏感配置。
- 目标 SSH 开放，且泄露口令可复用；admin 私钥被 root 信任（或私钥本身可读）。
- 需要字典/哈希爆破环境（hashcat/john 或在线库）。

## 利用步骤

1. 访问会报错的业务路由（原文 `http://<host>:8000/users/`），确认返回 Django 技术错误页。
2. 向下翻到 Settings / Environment 区块，查找 `JENKINS_AUTHORIZATION`、`JENKINS_URL`、`DATABASES`、`SECRET_KEY` 等配置。
3. 取 `JENKINS_AUTHORIZATION` 的 Basic 值，Base64 解码得到 `用户名:口令哈希`（原文 `admin:1172836bdd7cc687550e757a57d57e2804`）。
4. 对 32 位十六进制串做字典/规则爆破（原文得到 `P@ssw0rd_123`）；也可先查在线哈希库。
5. 用 `admin:P@ssw0rd_123` SSH 登录目标主机；在 admin 家目录查找 `id_rsa`/`.ssh` 私钥。
6. 用该私钥 `ssh root@<host> -i id_rsa`；若 root 信任该 key，直接获得 root 并读取 flag。
7. 若 Jenkins 内网可达，用泄露的 `JENKINS_URL` + Basic 凭据登录 Jenkins，继续 Jenkins Script Console 凭据解密链。

## PoC

```bash
# 1) 触发 Django 技术错误页
curl -s "http://TARGET:8000/users/"

# 2) 从页面 Settings 区块取 JENKINS_AUTHORIZATION
# JENKINS_AUTHORIZATION 'Basic YWRtaW46MTE3MjgzNmJkZDdjYzY4NzU1MGU3NTdhNTdkNTdlMjgwNA=='
echo 'YWRtaW46MTE3MjgzNmJkZDdjYzY4NzU1MGU3NTdhNTdkNTdlMjgwNA==' | base64 -d
# admin:1172836bdd7cc687550e757a57d57e2804

# 3) 哈希爆破（示例；原文得到 P@ssw0rd_123）
hashcat -m 0 1172836bdd7cc687550e757a57d57e2804 wordlist.txt

# 4) SSH 登录并复用 admin 私钥提权
ssh admin@TARGET
# 在目标上读取 admin 私钥后：
ssh root@TARGET -i id_rsa
```

## 变体与关联

- 若错误页被关闭，可尝试 Django 的 `/__debug__/`（django-debug-toolbar）、静态 `settings.py` 备份、`.env`、`/admin/` 报错等泄露面；也可从其他异常页（模板错误、数据库错误）触发 settings 输出。
- 泄露的 `SECRET_KEY` 可伪造 Django session/cookie、签名 token；泄露的 `DATABASES` 可直连数据库；本卡只展开 Jenkins Basic 凭据这一条。
- 与库内 Django 相关卡的区别：本卡不是 SSTI/反序列化/注入，而是 DEBUG 错误页直接 dump settings；与通用“调试接口泄露环境变量”卡类似，但载体是 Django 技术错误页。
- Jenkins 凭据拿到后若可登录后台，可继续“Script Console 读取 master.key/hudson.util.Secret 解密 credentials.xml”链。

## 检测与防御

- **关闭 DEBUG**：生产环境 `DEBUG=False`，使用自定义 404/500 页；确保异常页不渲染 settings/环境变量。
- **配置分离**：不要把第三方系统凭据、数据库口令、SECRET_KEY 放进可被错误页展示的 settings；使用密钥管理服务/环境变量，并限制读取权限。
- **强口令与哈希**：不要用可被字典爆破的弱口令派生值；对凭据做加密存储而非简单哈希；定期轮换。
- **SSH 卫生**：禁止口令登录或限制来源；admin 私钥不应被 root 信任；私钥文件权限 600；使用独立密钥与堡垒机。
- **检测**：监控响应中的 `Django Version`、`Settings`、`JENKINS_AUTHORIZATION`、`SECRET_KEY` 等特征；扫描生产环境 `DEBUG=True`；审计错误页是否暴露配置。
