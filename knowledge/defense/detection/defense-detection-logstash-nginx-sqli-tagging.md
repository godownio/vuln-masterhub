---
id: defense-detection-logstash-nginx-sqli-tagging
title: Logstash 解析 Nginx 访问日志并按正则标记 SQL 注入请求
type: scenario
domain: defense
path: defense/detection
technique: logstash-nginx-access-sqli-tagging
aliases:
- Nginx 日志 SQL 注入检测
- Logstash SQLi 检测规则
- ELK 注入告警
- access.log 注入特征匹配
tags:
- detection
- logstash
- elk
- nginx
- sqli
- grok
- elasticsearch
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:51:52+08:00'
  notes: 已对照原文核对：Filebeat采集nginx access.log→Logstash grok提取request→正则(union.*select|sleep|information_schema|or 1=1等)打attack_type=sql_injection→ES，截图5/6显示Kibana命中该注入请求。卡片已注明正则粗糙、select.*from可能误报、POST body不在access.log。无组件版本，未设versions
---

## 一句话结论

Filebeat 采集 Nginx `access.log`，Logstash 用 grok 拆出 `request` 字段后，以不区分大小写的正则匹配 `union select`、`information_schema`、`sleep(`、`or 1=1` 等特征，给命中的文档打上 `attack_type: sql_injection`，即可在 Elasticsearch/Kibana 中检索和告警。

## 原理

Nginx 的 `access.log` 默认记录完整请求行，包含方法、URI 及查询串，攻击载荷通常原样留在 `request` 字段中。Logstash 的 grok 把整行拆成 `client_ip`、`method`、`request`、`status`、`body_bytes_sent`、`user_agent` 等结构化字段后，对 `request` 做正则匹配。

命中的文档通过 `mutate { add_field }` 增加 `attack_type` 字段，写入 Elasticsearch 后即可用 `attack_type: sql_injection` 聚合、画图或触发告警。关键点在于：检测发生在请求已被 Web 服务器接受之后，日志本身就是证据；它不阻断请求，只负责发现与留痕。

## 触发条件

- Nginx 访问日志包含完整 request 行（默认 combined/main 格式即可）；
- Filebeat 能读取日志文件，并把 `fields.log_type` 正确带给 Logstash；
- Logstash grok 表达式与日志格式匹配，未出现 `_grokparsefailure`；
- 正则覆盖目标攻击的关键字；攻击者未对关键字做编码、注释拆分或大小写以外的混淆；
- 日志链路（Filebeat → Logstash → Elasticsearch）通畅。

## 利用步骤

1. 在 Filebeat 中增加 `nginx_access` 日志输入，输出到 Logstash 5044。
2. Logstash 用 grok 解析 combined 格式，提取 `client_ip`、`request`、`status` 等字段。
3. 对 `request` 应用 SQL 注入正则，命中后 `add_field` 打 `attack_type: sql_injection`。
4. 输出到按天滚动的 `secops-*` 索引。
5. 在 Kibana Discover 用 `attack_type: sql_injection` 检索，或按 `client_ip.keyword`、`request.keyword` 做聚合和告警。

## PoC

最小 Logstash 过滤片段：

```ruby
filter {
  if [fields][log_type] == "nginx_access" {
    grok {
      match => {
        "message" => "%{IPORHOST:client_ip} - %{DATA:ident} \[%{HTTPDATE:timestamp}\] \"%{WORD:method} %{DATA:request} HTTP/%{NUMBER:http_version}\" %{NUMBER:status:int} %{NUMBER:body_bytes_sent:int} \"%{DATA:referrer}\" \"%{DATA:user_agent}\""
      }
    }
    date {
      match => ["timestamp", "dd/MMM/yyyy:HH:mm:ss Z"]
      target => "@timestamp"
    }
    if [request] =~ /(?i)(union.*select|select.*from|sleep\(|benchmark\(|information_schema|or\s+1=1|'.*or.*')/ {
      mutate { add_field => { "attack_type" => "sql_injection" } }
    }
  }
}
```

可命中的样例日志：

```text
192.168.220.132 - - [14/Oct/2026:16:42:54 +0800] "GET /prod-api/system/user/list?username=1%27%20UNION%20SELECT%201,2,3--+ HTTP/1.1" 200 104 "-" "curl/7.81.0"
```

对应的空查询可命中 `%27` 编码后的 `UNION SELECT` 明文片段；若载荷把关键字全部 URL 编码，需先 `urldecode` 再匹配。

## 变体与关联

- 变体：先对 `request` 做 URL 解码/多重解码再匹配；增加 `status`、`body_bytes_sent`、`user_agent` 组合条件降低误报；接入 ModSecurity/CRS 告警日志做二次确认；用 Elasticsearch Watcher、ElastAlert 或 Python 脚本消费 `attack_type` 字段告警。
- 关联：`web/generic/sqli`（原 RuoYi 卡已删除）（被检测的注入场景）；[[defense-detection-ssh-bruteforce-alert-iptables-block]]（同一日志平台上的另一类告警与自动封禁）。
- 不确定点：原文正则较粗糙，只按关键字匹配，未给出误报率与绕过测试；`select.*from` 对正常搜索请求也可能误报。

## 检测与防御

- **规则设计**：匹配前做 URL 解码、大小写归一化、去注释，覆盖 `UNION/**/SELECT`、`%55nion`、内联注释、`SLEEP`/`BENCHMARK` 等变体；对 `select.*from` 这类宽泛规则加接口/参数白名单，避免业务搜索误报。
- **关联上下文**：同一 IP 短时间多次命中、状态码 200/500、响应体异常、命中后紧跟目录扫描，才提升为高优先级。
- **检测盲区**：纯时间盲注可能只含 `sleep` 或编码后的函数名；POST body 不在 Nginx access.log 的 request 行内，需应用/WAF 日志补采。
- **防御**：日志告警不能替代修复，根因仍是参数化查询与输入校验；WAF 做兜底；保留原始日志供溯源，注意日志中的敏感参数脱敏与访问控制。
