---
id: web-generic-static-upload-path-join-download-id-photo-bulk
title: 上传文件路径泄露后拼接静态资源路由批量下载用户证件照
type: scenario
domain: web
path: web/generic
technique: 文件路径拼接未授权下载
aliases:
- 文件路径拼接下载
- 静态资源路径泄露
tags:
- file-download
- path-leak
- bulk-data-leak
- pii
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-26
  verified_at: '2026-11-08T14:25:29+08:00'
  notes: 已对照原文核对：图17 idPhotoF/idPhotoZ 路径字段、图18 直拼 host 404 Whitelabel、图19 下载功能点泄露 /sys/common 路径、图20-21 拼接下载路由 200 回显、图22 浏览器直出证件照，请求/响应证据齐全；与目录浏览卡获取方式不同；未验证点：批量下载脚本未实际运行
---

# 上传文件路径泄露后拼接静态资源路由批量下载用户证件照

## 一句话结论

接口响应中返回的上传文件相对路径（如 idPhotoF/idPhotoZ 字段的 jpg 路径）直接拼到站点根域名会 404，因为文件实际由独立的静态资源/下载路由服务；从站内任意"文件下载"功能的数据包中找到真实存储路由（本例 `/sys/common/static/`）后，把泄露的相对路径拼接到该路由下即可未授权访问任意用户上传的身份证照片，结合批量接口泄露的路径列表可脚本化拉取全部（本例 7806 张）。

## 原理

很多框架（jeecg-boot 等）把上传文件存在服务器本地目录，通过一个通用下载/静态映射控制器（`/sys/common/static/**`）对外提供；业务接口只返回相对路径，前端再拼下载前缀。攻击者直接拼根域名命中的是前端路由而非文件服务，返回 Spring Boot Whitelabel 404。而任意一个"点击下载"功能触发的真实请求会暴露完整下载前缀，下载路由通常无逐文件鉴权，路径即唯一凭证，因此路径一旦批量泄露（分页接口未授权返回全部用户记录含文件路径），批量下载只是拼字符串的问题。

## 触发条件

- 业务接口响应包含上传文件的相对路径字段（idPhotoF/idPhotoZ/avatar/attachUrl 等）；
- 存在未鉴权或仅登录态校验的通用文件下载/静态资源路由；
- 文件名为服务端生成的随机串、无访问控制与有效期。

## 利用步骤

1. 在未授权的 list 接口响应中收集文件相对路径字段（idPhotoF/idPhotoZ）；
2. 先尝试 `https://host/<相对路径>`，确认返回 Whitelabel Error Page 404，排除根路径直拼；
3. 找站内任意"文件下载"功能点击下载，从 Burp 历史中获取真实下载 URL 形如 `GET /sys/common/static/<目录>/<hash>.jpg`；
4. 把收集的相对路径逐一拼接：`https://host/sys/common/static/<相对路径>`，浏览器访问回显身份证照片；
5. 脚本化批量：解析 list 响应 JSON 提取全部 idPhotoF 路径，拼接下载前缀逐个保存（7806 张）。

## PoC

见利用步骤中的 URL 拼接模式与 JSON 遍历脚本（requests 逐个 GET 保存即可）。

## 变体与关联

- 与本篇上游场景配合：list 接口未授权批量泄露（见接口粒度鉴权不一致卡）提供路径清单；
- 若下载路由校验 token，可尝试带低权限登录态或路径穿越绕过目录限制；
- 同类：OSS 签名 URL 过期失效但后端仍可拼接、nginx alias 配置错误目录穿越。

## 检测与防御

- 文件服务启用带签名与有效期的访问 URL（预签名），或按属主校验后再回传文件流；
- 通用下载路由禁止返回目录外文件，且对批量连续请求限速告警；
- 响应中避免返回完整可猜路径；上传目录禁用目录枚举。
