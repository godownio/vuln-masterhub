---
id: defense-forensics-phishing-infra-open-directory-phpmailer-credential-logs
title: 钓鱼邮件基础设施取证：开放目录下的 PHPMailer 发件页、品牌落地页与按 IP 保存的凭据日志
type: scenario
domain: defense
path: defense/forensics
technique: phishing-infra-open-directory-phpmailer-credential-logs
tags:
- forensics
- phishing
- email
- phpmailer
- open-directory
- credential-theft
- incident-response
- infrastructure
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V422
  verified_at: '2026-11-09T17:00:39+08:00'
  notes: 已对照原文与37张图片核对：/send 的 composer+PHPMailer 目录、test*.php 默认值（mail.naver.com、no-reply@sisileae.com、韩文主题、rtnurl base64）、/accounts 两个 Naver 仿冒落地页与跳转 nid.naver.com、/kakao 按 IP 日志及 authenticate.json 中 loginId/password=U2FsdGVkX1... 均有截图佐证。核对更正：原文/截图标注 GMT+1，实际巴黎 2024-05 为 UTC+2 夏令时，卡内已改为『巴黎当地时间（夏令时 UTC+2，原文标注 GMT+1）』；密码仅识别为 OpenSSL/CryptoJS salted AES 密文，未解密（卡内已注明未验证）。dedup top 候选为攻击侧页面克隆/自建 SMTP，视角不同。原文无受影响版本。
url: /docs/defense/forensics/defense-forensics-phishing-infra-open-directory-phpmailer-credential-logs/
draft: false
kb_aliases:
- 钓鱼站开放目录取证
- PHPMailer 发件页分析
- 仿冒 Naver 钓鱼套件
- 按 IP 凭据日志
- 钓鱼基础设施溯源
- 品牌仿冒落地页跳转
---

## 一句话结论

攻击者把整套钓鱼套件托管在 VPS 上时，若 Web 服务器未关闭目录列表，`/send`（composer + PHPMailer 发件页）、`/accounts`（仿冒品牌落地页）、`/kakao`（按受害者 IP 命名的请求日志）会全部暴露；从发件页默认值可还原发件服务器、伪装发件人与钓鱼链接，从落地页可还原品牌仿冒与跳转的真实登录站，从日志中的登录请求体可直接提取受害邮箱与密码字段（可能是目标站前端 JS 加密后的密文），从而完成发件配置、受害者清单与凭据外泄证据的三位一体取证。

## 原理

- **开放式钓鱼套件结构**：典型目录分工是 `/send` 放邮件发送页面（`test.php`、`test1.php`…）与 composer 依赖（`composer.json/lock/phar`、`vendor/autoload.php`、`vendor/phpmailer/phpmailer`），`/accounts` 放仿冒品牌的 HTML 落地页，`/kakao`（或按品牌/项目命名）按受害者 IP 建立子目录保存原始 HTTP 请求/响应。Apache 默认的 `Index of /` 目录列表让防守方可以直接枚举。
- **发件页即模板**：页面直接渲染 `ServerName`、`SendTime`、`FromName`、`FromEmail`、`ToName`、`Subject`、`URL`、`Message` 等默认值。示例使用 `mail.naver.com` 作为 SMTP 服务器、`no-reply@sisileae.com` 作为伪装发件人、韩文主题「[네이버] 메일 송수신 기능 제한 알림」（Naver 邮件收发功能限制通知），正文 `Hello!`；这说明发件页是批量群发模板，攻击者只需改收件人。
- **链接嵌套编码**：`URL` 字段里的 `nid.oksite.eu/nidlogin.login?...&rtnurl=<base64>` 外层是仿冒 Naver 登录入口，`rtnurl` 的 base64 解码后是 `/user2/help/myInfo?m=viewChangePasswd&lang=ko`（修改密码页）。两层 URL 的组合用于把“账号异常→改密”的诱导落到攻击者控制的域名。
- **时区与品牌矛盾**：页面 `SendTime` 与韩国标准时间不一致，换算后对应法国巴黎当地时间（2024-05 夏令时为 UTC+2，原文/截图按标准时标注为 GMT+1），而邮件冒充韩国 Naver；这类时区/语言/品牌不一致是基础设施归属与操作者画像的高价值线索。
- **落地页借真站收口**：`deletegoogle.html`、`deletekakao.html` 使用 Naver 绿色品牌头与韩文文案「通过 Naver 账号创建的 Google/Kakao 账号已删除」，制造“账号被处理”的紧迫感；页面随后跳转到真实的 `nid.naver.com/nidlogin.login?...&url=https://mail.naver.com/`。真实登录页会降低受害者戒心，而钓鱼套件在前端或代理层截获提交内容。
- **按 IP 日志的价值**：日志目录以受害者公网 IP 命名，文件保存完整请求/响应（`request-url`、`Host`、`User-Agent`、`Cookie`、POST body 等）。示例日志中 `accounts.kakao.com/api/v2/login/authenticate.json` 的 JSON 含 `loginId`（受害邮箱）、`password`（`U2FsdGVkX1...`，即 OpenSSL/CryptoJS salted AES 密文）、`csrf`、`loginUrl` 等；说明套件在登录提交环节截获了凭据。密码字段是目标站前端加密后的密文，若要还原明文仍需目标站页面 JS 中的密钥（本文未解密，属未验证环节）。
- **为什么这是可复用的取证路径**：钓鱼套件为了“打点即用”常整站打包上传，目录列表、`VERSION` 文件、composer 依赖、按 IP 日志都是通用痕迹；即使目录列表被关闭，也可从泄露的备份、日志路径或邮件中的链接反推同构目录。

## 触发条件

- 已发现可疑钓鱼域名/邮件，且站点目录列表可访问（或取得钓鱼服务器镜像/备份/日志）。
- 分析在授权范围内进行；访问第三方站点时只做必要的只读请求并留存证据。
- 邮件样本、邮件头或受害者报告可提供钓鱼域名与时间范围。

## 利用步骤

1. **枚举目录**：访问 `/`、`/send/`、`/accounts/`、`/<brand>/` 等路径，记录 `Index of` 列表、文件大小与修改时间；保存页面快照与哈希。
2. **确认发件组件**：在 `/send` 识别 `composer.json/lock/phar` 与 `vendor/`；查看 `vendor/phpmailer/phpmailer/VERSION` 确认 PHPMailer 版本（示例 6.9.1），记录 `autoload.php` 与 `get_oauth_token.php` 等文件。
3. **读发件页默认值**：打开 `test*.php`，记录 SMTP 服务器、FromName/FromEmail、Subject、URL、Message；对 URL 中的 base64 参数解码，得到真实钓鱼路径。
4. **读落地页**：打开 `delete*.html`，记录仿冒品牌、文案与跳转目标（真实登录域名）；对比页面语言与时区，形成归属线索。
5. **解析日志**：逐个 IP 目录读取请求/响应，抽取 `request-url`、`Host`、`User-Agent`、POST body 的 `loginId`/`password`/`csrf` 等字段；按 IP 汇总受害邮箱、登录时间与密码密文。
6. **识别密文格式**：`U2FsdGVkX1...` 为 `Salted__` 前缀的 base64，属 OpenSSL/CryptoJS AES 加盐格式；记录但不要误报为明文口令，解密需目标站 JS 密钥（未取得前不作为已还原凭据）。
7. **交叉与输出**：与邮件样本头、SMTP 日志、域名注册/解析信息交叉，输出 `IOC`（域名、IP、发件地址、URL 路径）、受害者清单与时间线；通知品牌方与受害者改密、封禁基础设施，并按流程保全证据。

## PoC

```bash
# 只读枚举开放目录（授权范围内）
curl -s https://<phish-host>/send/    | tee send_index.html
curl -s https://<phish-host>/accounts/ | tee accounts_index.html
curl -s https://<phish-host>/<brand>/  | tee logs_index.html

# 解码钓鱼链接中的 base64 参数
python -c "import base64; print(base64.b64decode('<rtnurl-value>').decode())"
# 示例解码结果形如：https://<phish-host>/user2/help/myInfo?m=viewChangePasswd&lang=ko

# 从按 IP 日志中提取登录 JSON
grep -a '"loginId"' <ip>/<logfile> | head
# 形如 {..."loginId":"victim@example.com","password":"U2FsdGVkX1..."...}
```

## 变体与关联

- 目录列表关闭时：尝试常见备份/日志路径、robots.txt、编辑器残留文件；从邮件链接的路径结构反推 `/send`、`/accounts` 等目录。
- 发件组件可能换成其它 SMTP 库或自建 SMTP；判断依据是 `vendor/` 依赖、`VERSION` 文件与页面默认值，而非固定文件名。
- 品牌仿冒对象可换（Naver/Kakao/Daum 等），落地页跳转也可能指向仿冒登录页而非真实站；跳转目标是区分“借真站收口”与“假登录页直接收凭据”的关键。
- 密码字段可能是目标站前端加密密文；若取得目标站 JS 与密钥，可按前端 AES 还原（见 CryptoJS/JS AES 参数还原类卡片），本条未验证。
- 关联：[[defense-forensics-email-header-spoof-detection]]（邮件头伪造与硬信号判定）、[[defense-incident-response-supply-chain-phishing-fake-login-attribution]]（仿冒登录页取证与域名归属）、[[pentest-initial-access-forward-phishing-selfhosted-smtp-spf-bypass]]（攻击侧自建 SMTP 转发钓鱼）。

## 检测与防御

- **检测**：监控新注册/新解析域名中出现目标品牌关键词与登录路径；邮件网关对“发件域与品牌不符、时区/语言矛盾、正文仅一句问候 + 改密链接”的模板化邮件告警；对 `U2FsdGVkX1` 开头的密码字段识别为前端加密凭据而非明文。
- **防御**：企业侧启用 DMARC 拒绝与品牌域名监控；员工收到“账号被删除/功能受限”类通知时只从官方入口登录；禁用邮件中的可执行/脚本附件并沙箱化链接。
- **攻击者侧反取证提示（用于理解痕迹）**：关闭目录列表、把发件页与日志分离到不同主机、日志加密存储并限制访问；但按 IP 目录与整站打包仍是常见 OPSEC 失误。
- **取证规范**：只读访问、记录 URL/时间/响应哈希；涉及受害者凭据时按隐私与合规要求脱敏、加密保管，不尝试登录受害者账号。
