---
id: cloud-cloud-iam-frontend-sign-replay-uploadossdata-sts-bucket-takeover
title: 前端签名可复现的 OSS 上传配置接口：伪造 MD5 签名获取阿里云 STS 并接管对象存储
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: frontend-sign-replay-uploadossdata-sts-bucket-takeover
tags:
- cloud
- aliyun
- oss
- sts
- credential-leak
- signature
- sourcemap
- miniprogram
- bucket-takeover
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T09:06:04+08:00'
  notes: '已对照原文全文与 24/24 截图核对：img05 sourceMappingURL=app.86f89465.js.map、img06/07 map sources、img09 还原源码 src/api/index.js 中 signKey 常量与 getSign/fetch、img10 uploadOssData/uploadOssSave/uploadLocal 接口、img12/13 小程序 getUploadOssData 的 name 参数与 getSign(sort(params)+''key=''+signKey, MD5 大写)、img15 Authorization: Bearer undefined 且 sign 缺 name 时返回『文件名称不能为空』、img16 带 name 成功返回 code 0 与 credentials_data(access_key_id STS./access_key_secret/sts_token/bucket=jhst-test/region=oss-cn-beijing)、img17-18 OSS Browser STS 登录取 35 bucket、img19-21 18.41GB ECS raw 备份/1.38GB 生产日志/SQL 与 uploads.gz、img23 alicloud-tools 全国地域 ECS 均 0 台。worker 对 ''Bearer undefined'' 的修正成立：接口只验客户端签名、未拒绝无效 Authorization，卡片表述准确。原文未给版本，已 clear。与同 sink 的 cos-oss-temp-credential-leak-overwrite(prepare 接口无签名门禁+put_object 覆盖)触发条件/PoC/利用目标不同，判为并列保留，并已在本卡『变体与关联』补上同 sink 交叉链接(核对时修正)。'
url: /docs/cloud/cloud-iam/cloud-cloud-iam-frontend-sign-replay-uploadossdata-sts-bucket-takeover/
draft: false
kb_aliases:
- uploadOssData 接口
- OSS 上传配置接口泄露 STS
- MD5 签名伪造
- signKey 前端泄露
- 阿里云 STS Token 接管 OSS
- OSS Browser STS 登录
- alicloud-tools STS
---

## 一句话结论

H5 前端的 source map 泄露了 `signKey`，小程序代码又暴露了参数名 `name`，而 `POST /Backend/Common/Common/uploadOssData` 只校验客户端可复现的 `sign=MD5(sort(params)+"key="+signKey).toUpperCase()`、不校验登录态（请求里甚至是 `Authorization: Bearer undefined`）；按算法伪造 `name/timestamp/nonce/sign` 即可让接口返回阿里云 `access_key_id`/`access_key_secret`/`sts_token`/`bucket`/`region`，用 OSS Browser 以 STS 登录后可列举 35 个 bucket，读取 18.41GB ECS 系统备份、1.38GB 生产日志与 SQL 备份。

## 原理

- **签名密钥在前端**：H5 的 `src/api/index.js` 中 `const signKey = '...'` 与 `getSign/fetch` 一起打包；生产环境未关闭 source map，攻击者用 `reverse-sourcemap` 还原源码后直接拿到签名算法与密钥。签名算法为对参数按键排序拼接（`sort(params)`）后追加 `key=<signKey>`，再 `MD5(...).toUpperCase()`。
- **接口只验签不验登录**：请求头 `Authorization: Bearer undefined` 仍返回业务响应，说明服务端没有真正校验会话，只依赖客户端签名；签名密钥公开在前端，等于没有认证。
- **参数名来自小程序**：H5 接口要 `name`（文件名称），攻击者先用 `file`/`filename` 均失败，回到小程序 `app-service.js` 看到 `post("/V1/"+CARRIER_TYPE+"/User/uploadOssData", { name: i })`，改用 `name` 后成功；这是跨端（H5 源码 + 小程序代码）拼合信息的典型点。
- **接口返回 STS 而非长期 AK/SK**：响应 `data.credentials_data` 含 `access_key_id`（`STS.` 前缀）、`access_key_secret`、`sts_token`、`bucket`、`region`，还有 `save_path`；STS 是临时凭证，但有效期内权限与 RAM 角色一致。
- **STS 接管 OSS**：阿里云 OSS Browser 的“授权码登录”支持 AccessKeyId + AccessKeySecret + STS Token 三项；登录后可列出该账号下所有可见 bucket（本例 35 个），浏览/下载/上传/删除对象。
- **为什么危害大**：bucket 中常见 ECS 系统盘 raw 备份（18.41GB）、生产服务器日志（1.38GB）、数据库 SQL 备份（7.91MB/983KB）、`uploads.gz`（265MB）等；这些数据可导致源码、数据库、日志中的凭据与用户数据泄露。STS 的权限边界决定能否进一步横向到 ECS：本例用 alicloud-tools 以 `--sak --ssk --sts --token` 扫描所有地域 ECS 均为 0 台，说明该 STS 遵循了最小权限，只授予 OSS。
- **与长期 AK/SK 泄露的区别**：STS 会过期，但泄露路径不同（签名接口按需签发）、且常被误认为“临时凭证所以安全”；只要接口可反复调用，攻击者可在需要时重新获取新的 STS。

## 触发条件

- 前端 bundle 或 `.js.map` 可访问，泄露签名算法与 `signKey`（或签名算法不含密钥、可离线重算）。
- 上传配置/初始化接口（如 `/Backend/Common/Common/uploadOssData`）只校验客户端签名，不校验登录态、不做速率限制。
- 接口按参数返回 OSS 临时凭证（`access_key_id`/`access_key_secret`/`sts_token`）与 bucket/region。
- STS 策略至少允许 `ListBuckets`、`ListObjects`、`GetObject`，bucket 中有业务备份/日志/数据库等敏感数据。
- 攻击者能访问目标 H5/小程序后端域名与阿里云 OSS 公网端点。

## 利用步骤

1. 在 H5 前端发现 `.js.map`（`//# sourceMappingURL=`），用 `reverse-sourcemap`/shuji 还原源码。
2. 在 `src/api/index.js` 等文件找到 `getSign`/`fetch`：确认签名串构造（`sort(params) + 'key=' + signKey`）与 `signKey` 常量。
3. 从小程序解包代码（`app-service.js`）确认接口路径与参数名（本例 `/V1/<CARRIER_TYPE>/User/uploadOssData`、`name`）。
4. 构造请求：`name` 为目标文件名，`timestamp` 当前秒级时间戳，`nonce` 随机字符串，`sign = MD5(sort({name,timestamp,nonce}) + "key=" + signKey).toUpperCase()`；`POST /Backend/Common/Common/uploadOssData`。
5. 解析响应 `data.credentials_data`，取出 `access_key_id`/`access_key_secret`/`sts_token`/`bucket`/`region`（响应可能对 `/` 转义，替换 `\/` 为 `/`）。
6. 用 OSS Browser“授权码登录”填入 Endpoint（默认公共云/HTTPS）、AccessKeyId、AccessKeySecret、STS Token；登录后枚举 bucket。
7. 按 bucket 名称/大小筛选备份、日志、数据库、上传目录；只读抽样证明影响，避免全量下载。
8. 若需评估横向：用 alicloud-tools 等支持 STS 的工具测试 ECS/RAM 权限；本例全部地域 ECS 为 0，确认最小权限后停止。

## PoC

签名与请求（伪代码，参数按目标替换）：

```python
import hashlib, time, random, string, requests

sign_key = "<从 source map 还原的 signKey>"
name = "test.jpg"
ts = str(int(time.time()))
nonce = ''.join(random.choices(string.hexdigits.lower(), k=32))

# 按前端 sort(params) 的实际拼接规则实现（键排序后 key=value&...）
base = f"name={name}&nonce={nonce}&timestamp={ts}"
sign = hashlib.md5((base + "key=" + sign_key).encode()).hexdigest().upper()

r = requests.post(
    "https://<test-domain>/Backend/Common/Common/uploadOssData",
    json={"name": name, "timestamp": ts, "nonce": nonce, "sign": sign},
)
print(r.json())   # data.credentials_data: access_key_id / access_key_secret / sts_token / bucket / region
```

```text
# OSS Browser 授权码登录字段：
# Endpoint: 默认（公共云）/ HTTPS
# AccessKeyId: STS.xxxxxxxx
# AccessKeySecret: xxxxxxxx
# STS Token: CAISuQJ1q6Ft5...
#
# alicloud-tools 检查 STS 是否可横向 ECS：
# ./AliCloud-Tools --sak STS.xxx --ssk xxx --sts --token CAISuQJ... ecs --list
```

说明：`sort(params)` 的具体拼接分隔符以恢复出的 JS 为准（原文为排序后拼接再追加 `key=`）；签名大小写、时间戳单位（秒）必须与前端一致，否则服务端拒绝。

## 变体与关联

- **泄露源变体**：source map、未混淆 bundle、小程序包、接口文档、GitHub；签名密钥可能叫 `signKey`、`secret`、`appSecret`。
- **凭证类型变体**：接口可能返回长期 AK/SK（见 [[cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof]]、[[cloud-cloud-iam-frontend-js-alibaba-ak-sk-cloud-takeover]]）或 STS；STS 过期后若接口仍可调用，可重新签发。
- **同 sink 对照**：[[cos-oss-temp-credential-leak-overwrite]]（prepare/签名接口直接返回临时凭证后用 SDK `put_object` 写入/覆盖，无签名门禁）；本卡门禁是可复现的客户端 MD5 签名，利用重点是读取 bucket 中的备份与日志。
- **STS 横向变体**：若 STS 策略含 ECS/RAM 权限，可用 [[cloud-cloud-iam-aliyun-temp-credential-cf-console-takeover]] 的 CF 工具列权、创建 RAM 后门用户；本例最小权限，ECS 扫描为 0。
- **签名复现对照**：[[mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration]]（小程序 MD5(json+timestamp) 签名重算）、[[mobile-miniprogram-aes-cbc-rsa-wrapped-iv-key-sign-replay]]（AES/RSA 包裹的 sign 重放）。
- **路径来源**：[[pentest-recon-sourcemap-leak-frontend-source-restore-api-discovery]]（source map 还原源码并发现隐藏接口）、[[pentest-recon-miniprogram-unpack-test-domain-fofa-backend-pivot]]（小程序解包找到测试环境域名）。
- **边界**：signKey 轮换/接口加登录态/IP 白名单/STS 最小权限仅 OSS 读、bucket 中无敏感数据时，危害降级；STS 过期后需重新调用接口获取。

## 检测与防御

- **开发侧**：不要把签名密钥放在前端；需要客户端签名的接口应在服务端绑定用户会话/设备凭证，并对签名密钥做服务端保管与轮换；上传配置接口必须校验登录态与权限，STS 按用户/操作最小化（仅允许指定 bucket/前缀/动作）。
- **前端发布**：生产环境关闭 source map、移除调试配置与测试域名；签名算法可以被逆向，不能作为认证边界。
- **云侧**：STS 策略最小化（`oss:ListBuckets`/`oss:GetObject` 按 bucket/前缀限制）、设置短有效期；开启 OSS 访问日志与 ActionTrail，监控异常 `ListBuckets`/大批量 `GetObject`、来自非常用 IP 的 STS 调用。
- **监测**：对 `uploadOssData` 类接口做未授权/重放测试与速率限制；监控 source map 文件是否可公开访问（`*.js.map` 返回 200）；定期审计 bucket 中是否存放系统备份、数据库、日志等敏感数据，敏感备份加密/分账号存放。
- **响应**：发现泄露后立即轮换签名密钥、作废 STS/相关 RAM 凭证，关闭 source map 与测试环境入口；审计 bucket 访问日志，确认是否被下载；复核 STS 策略与 RAM 权限边界。
