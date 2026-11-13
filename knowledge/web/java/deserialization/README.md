# Java 反序列化

## 这层是什么

原生反序列化、gadget 链、触发点、绕过与利用。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- [Comparator 链](comparator/README.md) —— 通过 Comparator/compare 触发 toString、hashCode 等方法的 gadget 组合。
- [JDK 原生链](jdk/README.md) —— JDK 内置类形成的反序列化链与触发点。
- [Fastjson](fastjson/README.md) —— Fastjson AutoType、缓存与绕过。
- [Jackson](jackson/README.md) —— Jackson 多态反序列化与 gadget。
- [XStream](xstream/README.md) —— XStream 反序列化与 CVE 利用。
- [Hessian](hessian/README.md) —— Hessian 反序列化与利用链。
- [JNDI 注入](jndi/README.md) —— JNDI/LDAP/RMI 注入与高版本绕过。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AbstractAction.readObject 同名键触发 putValue→firePropertyChange→XString.equals 任意 toString](web-java-deserialization-abstractaction-putvalue-firepropertychange-xstring-tostring.md) | verified | high | 2026-11-07 |
| [ActiveMQ CVE-2023-46604 不出网利用：IniEnvironment 加载 Shiro INI 触发 getter/setter 链](web-java-deserialization-activemq-46604-intranet-ini-environment-getter-setter.md) | verified | high | 2026-11-05 |
| [ActiveMQ CVE-2023-46604 经多层代理的 XML 外带 RCE 与反弹 shell](web-java-deserialization-activemq-46604-proxied-xml-rce.md) | verified | high | 2026-11-07 |
| [ActiveMQ OpenWire 反序列化任意 String 构造方法致 RCE（CVE-2023-46604）](web-java-deserialization-activemq-openwire-throwable-constructor-rce.md) | verified | high | 2026-11-05 |
| [Adobe ColdFusion CVE-2023-29300：WDDX StructHandler 任意类 setter 注入，JdbcRowSetImpl 触发 JNDI RCE（未授权 filemanager.cfc）](web-java-deser-coldfusion-cve-2023-29300-wddx-setter-jndi.md) | verified | high | 2026-11-12 |
| [Allegra renderFieldMatch 反序列化：ExcelFieldMatchBL 读取 listmapping 直接 ObjectInputStream.readObject（CVE-2024-22505）](web-java-deserialization-allegra-renderfieldmatch-listmapping.md) | verified | medium | 2026-11-11 |
| [Apache Camel JMS ObjectMessage 自动反序列化导致 RCE（CVE-2026-40860）](web-java-deserialization-camel-jms-objectmessage-rce.md) | verified | high | 2026-11-05 |
| [Apache Causeway ViewModel Bookmark memento 反序列化 RCE：URL 片段经 GZip+Base64 还原对象（CVE-2025-64408）](web-java-deserialization-causeway-viewmodel-bookmark-memento-rce.md) | verified | high | 2026-11-05 |
| [Apache DolphinScheduler K8s 命名空间 SnakeYAML loadAs 反序列化 RCE（CVE-2023-49109）：伪造 k8s API 绕过 namespace 存在校验](web-java-deserialization-dolphinscheduler-k8s-namespace-snakeyaml-loadas-rce.md) | verified | high | 2026-11-11 |
| [Apache NiFi GetAsanaObject 缓存状态反序列化（CVE-2025-66524）：可写 MapCache 即触发 ObjectInputStream.readObject](web-java-deserialization-nifi-getasanaobject-cache-state-deser.md) | verified | medium | 2026-11-05 |
| [Axis server-config.wsdd 隐藏服务反序列化：allowedMethods=* 的 receiveData 直通 readObject](web-java-deserialization-axis-wsdd-hidden-service-readobject.md) | verified | low | 2026-11-06 |
| [BAVE(val=POJONode(SignedObject(业务类))) 绕过 resolveClass 黑名单：把被封禁的自研类偷渡回内层流，触发其 readObject 里的 SSRF 拉文件落盘](web-java-deser-bave-pojonode-signedobject-business-class-readobject-ssrf-filewrite.md) | verified | medium | 2026-11-09 |
| [C3P0 PoolBackedDataSourceBase 反序列化经 ReferenceableUtils 远程加载类](web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader.md) | verified | high | 2026-11-05 |
| [C3P0 反序列化不出网利用：Tomcat BeanFactory 结合 ELProcessor 执行命令](web-java-deser-c3p0-beanfactory-el-no-egress.md) | verified | high | 2026-11-05 |
| [CC 3.2.1 黑名单绕过：TransformedList.set + LazyList.get + InvokerTransformer 触发任意方法](web-java-deser-commonscollections-transformedlist-invoker-arbitrary-method.md) | verified | medium | 2026-11-07 |
| [CC 3.2.2 禁用 Transformer 后借 Hutool JSONObject 自动调用 getter 绕过](web-java-deser-commonscollections-322-jsonobject-getter-bypass.md) | verified | medium | 2026-11-05 |
| [CC 黑名单绕过：FactoryTransformer.create→InstantiateFactory 实例化 TrAXFilter 加载 TemplatesImpl](web-java-deser-cc-factorytransformer-instantiatefactory-traxfilter.md) | verified | high | 2026-11-08 |
| [CC1 LazyMap + AnnotationInvocationHandler 动态代理触发链](web-java-deser-commonscollections-cc1-lazymap-proxy.md) | verified | high | 2026-11-05 |
| [CC1 TransformedMap + AnnotationInvocationHandler 反射链执行命令](web-java-deser-commonscollections-cc1-transformedmap.md) | verified | high | 2026-11-05 |
| [CC11（CommonsCollections 3.2.1）LazyMap+TiedMapEntry+InvokerTransformer 驱动 TemplatesImpl 绕过 ChainedTransformer 黑名单](web-java-deserialization-cc11-lazymap-tiedmapentry-templatesimpl-no-chainedtransformer.md) | verified | high | 2026-11-08 |
| [CC3 变体：InvokerTransformer 直调 TemplatesImpl.newTransformer 的 CC1/CC6 触发器与字节码加载条件](web-java-deser-commonscollections-cc3-invokertransformer-newtransformer-variant.md) | verified | high | 2026-11-07 |
| [CC5 BadAttributeValueExpException + TiedMapEntry.toString 触发 LazyMap](web-java-deser-commonscollections-cc5-badattribute-tostring.md) | verified | high | 2026-11-05 |
| [CC6 触发 + CC3 TemplatesImpl 攻击的 Commons Collections 组合链](web-java-deser-commonscollections-cc6-cc3-templatesimpl.md) | verified | high | 2026-11-05 |
| [CC7 Hashtable reconstitutionPut + AbstractMap.equals 触发 LazyMap](web-java-deser-commonscollections-cc7-hashtable-equals-lazymap.md) | verified | high | 2026-11-05 |
| [CC8 变体：HashSet.hashCode 入口 + InvokerTransformer 构造 URLClassLoader 远程加载类 Z](web-java-deser-cc8-hashset-urlclassloader-remote-class.md) | verified | high | 2026-11-08 |
| [Commons Collections4 Transformer 链内复用同一对象完成两段式反射调用](web-java-deser-cc4-transformer-reuse-object-multicall.md) | verified | high | 2026-11-05 |
| [CommonsCollections6 经典链：HashMap/HashSet 触发 TiedMapEntry.hashCode→LazyMap.get→InvokerTransformer 执行 Runtime.exec（含假 Transformer/反射改 iTransformers/remove 键的构造时序）](web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer.md) | verified | high | 2026-11-07 |
| [Cookie userInfo Java 反序列化 + SpringEcho 无出网回显：CC8/TemplatesImpl 载荷直接命令执行](web-java-deserialization-cookie-userinfo-cc8-springecho.md) | verified | high | 2026-11-07 |
| [CSS 反序列化 + StringValueTransformer + JSONArray：把 transform 桥接成 toString 触发 TemplatesImpl](web-java-deser-stringvaluetransformer-css-jsonarray-templatesimpl.md) | verified | high | 2026-11-05 |
| [CVE-2019-17571：Log4j 1.2.x SimpleSocketServer 接收 socket 数据直接 ObjectInputStream 反序列化（CC1 RCE）](web-java-deserialization-log4j1-simplesocketserver-cve-2019-17571.md) | verified | high | 2026-11-13 |
| [CVE-2024-32030 Kafka UI JMX RMI 反序列化：Scala SerializedLambda 链设置 enableUnsafeSerialization 绕过 CC 3.2.2](web-java-deser-kafka-ui-jmx-scala1-cc322-property-bypass.md) | verified | high | 2026-11-08 |
| [Datart 资源导入 GZIP 包裹原生反序列化：multipart 上传 .ser.gz 触发 CommonsBeanutils1 命令执行（CVE-2024-12994）](web-java-deserialization-datart-import-resource-gzip-readobject.md) | verified | high | 2026-11-08 |
| [Dubbo readThrowable 隐式 toString（CVE-2023-29234）：伪造 RESPONSE_WITH_EXCEPTION 在客户端/服务端触发 toString gadget](web-java-deser-dubbo-readthrowable-implicit-tostring.md) | verified | medium | 2026-11-12 |
| [FineReport channel 反序列化实战：FrChannel 注入内存马与 suo5 内网隧道](web-java-deserialization-finereport-channel-frchannel-memshell-suo5.md) | verified | medium | 2026-11-05 |
| [gRPC bytes 字段承载 Java 原生序列化：grpcurl 枚举 + ysoserial CC5 RCE](web-java-deserialization-grpc-bytes-field-ysoserial.md) | verified | high | 2026-11-12 |
| [Gson fromJson 任意类实例化：可控类名 + 无参构造器副作用，选 sun.print.PrintServiceLookupProvider 经 execCmd 执行命令](web-java-deser-gson-fromjson-classname-printservicelookup-rce.md) | verified | high | 2026-11-10 |
| [Hibernate getter + ActivatableRef.getRef 触发 JRMP 二次反序列化绕过类名黑名单](web-java-deser-hibernate-activatableref-jrmp-secondary-bypass.md) | verified | medium | 2026-11-06 |
| [Hibernate getter 链直达 TemplatesImpl：HashMap 触发 TypedValue/ComponentType/PojoComponentTuplizer→GetterMethodImpl 反射 getOutputProperties（含 com.fr.third 重打包适配）](web-java-deser-hibernate-componenttype-getter-templatesimpl.md) | verified | high | 2026-11-12 |
| [Hodoku 数独客户端 .hsol 存档导入触发 XMLDecoder 反序列化 RCE（CVE-2024-51363）：zip 内 XML 直接交给 readObject](web-java-deserialization-xmldecoder-hodoku-hsol-puzzle-rce.md) | verified | medium | 2026-11-08 |
| [Hutool PooledDSFactory.getDataSource 当反序列化里的"任意 getter → JDBC 连接" sink：getter 被 Jackson/POJONode 触发即连 H2，init=runscript from 远程 SQL 落地命令执行](web-java-deser-hutool-pooleddsfactory-getdatasource-h2-runscript.md) | verified | high | 2026-11-08 |
| [IBM Db2 JCC createLicenseCache 触发本地 jccServerListCache.bin 反序列化](web-java-deserialization-ibm-jcc-serverlistcache-getconnection.md) | verified | high | 2026-11-05 |
| [Ignition JavaSerializationCodec WebSocket 数据通道反序列化 RCE（CVE-2023-39476）：ws-control 注册 incoming 连接后 POST ws-datachannel 触发 readObject](web-java-deser-ignition-javaserializationcodec-ws-datachannel-rce.md) | verified | high | 2026-11-13 |
| [Ignition StoreAndForward XML 导入 Base64 反序列化 RCE（CVE-2023-50220）](web-java-deser-ignition-storeforward-xml-base64-jython-pymethod.md) | verified | high | 2026-11-12 |
| [ImmutableSetMultimap 空 key 检查触发 JSONArray toString：checkEntryNotNull 桥接 DruidXADataSource + HSQL 二次反序列化](web-java-deserialization-immutablesetmultimap-nullkey-checkentrynotnull-tostring.md) | verified | high | 2026-11-05 |
| [ImmutableSetMultimap 经 UsingToStringOrdering 触发 JSONArray getter，再走 DruidXADataSource + HSQL 二次反序列化](web-java-deserialization-immutablesetmultimap-usingtostring-jsonarray-hsql.md) | verified | medium | 2026-11-05 |
| [Jackson POJONode.toString 经 Spring AOP 代理在 JDK17 触发 TemplatesImpl](web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17.md) | verified | high | 2026-11-05 |
| [Java 反序列化 payload 长度压缩：Unsafe 空字段、去调试信息与 Deflate 短链](web-java-deserialization-payload-length-compression.md) | verified | high | 2026-11-05 |
| [Java 反序列化过滤器 rootChecked 短路：只校验首个白名单类导致 gadget 绕过](web-java-deserialization-filter-rootchecked-first-class-bypass.md) | verified | high | 2026-11-05 |
| [Java 反序列化黑名单绕过：TextAndMnemonicHashMap 触发 POJONode.toString，Jackson 调用 getter 经 url 前缀绕过走 URLClassLoader.addURL 两段加载 RCE](web-java-deserialization-pojo-getter-urlclassloader-uriprefix.md) | verified | medium | 2026-11-08 |
| [Java 自定义序列化钩子：ObjectStreamClass 只识别 private 的 readObject/writeObject/readObjectNoData，public 版本不执行](web-java-deser-objectstreamclass-private-readobject-hook.md) | verified | high | 2026-11-09 |
| [JDBC URL WAF 绕过：利用驱动解码与参数解析差异绕过 autoDeserialize 过滤](web-java-deserialization-jdbc-url-waf-parser-bypass.md) | verified | medium | 2026-11-05 |
| [JDK 21 下用外部 Xalan-J TemplatesImpl 替代被封装的 Sink](web-java-deserialization-external-xalan-templatesimpl-sink.md) | verified | medium | 2026-11-05 |
| [JDK17 原生反序列化：EventListenerList 触发 Spring AOP 链反射调用 TemplatesImpl](web-java-deser-spring-aop-jdk17-templatesimpl-chain.md) | verified | high | 2026-11-05 |
| [JRMPClient 反序列化投递：UnicastRef+RemoteObjectInvocationHandler 使目标回连恶意 JRMPListener，再反序列化 Jackson1（JDK 8u191+ codebase 禁用时的替代）](web-java-deser-jrmpclient-unicastref-jackson1.md) | verified | high | 2026-11-10 |
| [Kryo 4.0.1 指定类型 readObject(HashMap.class) 仍经 MapSerializer→readClassAndObject：CommonsBeanutils BeanComparator 触发 JdbcRowSetImpl JNDI（CVE-2024-0252）](web-java-deser-kryo-typed-readobject-hashmap-beancomparator-jndi.md) | verified | medium | 2026-11-12 |
| [Kryo readClassAndObject 反序列化：HashMap.put 触发 hashCode，链到 TemplatesImpl 与 Jackson XString](web-java-deser-kryo-hashmap-hashcode-gadget-chain.md) | verified | high | 2026-11-11 |
| [Kryo 反序列化 UTF-8 Overlong Encoding 混淆：类名/字段/数组/Map 超长编码绕过字节黑名单与 WAF](web-java-deser-kryo-utf8-overlong-encoding-bypass.md) | verified | medium | 2026-11-10 |
| [Kryo 配置反射滥用：JSON 键驱动 setter，关闭 RegistrationRequired 并设 StdInstantiatorStrategy 解锁 gadget](web-java-deser-kryo-setter-reflection-instantiator-registration-bypass.md) | verified | high | 2026-11-11 |
| [mapdb linked record 指针改写：8 字节目录穿越写把反序列化重定向到分段 Payload](web-java-deserialization-mapdb-linked-record-pointer-rewrite-deser-rce.md) | verified | medium | 2026-11-06 |
| [MyFaces client viewState 反序列化：密钥已知时用 EL gadget 链 RCE](web-java-deserialization-myfaces-client-viewstate-el.md) | verified | medium | 2026-11-05 |
| [MySQL JDBC 不出网利用：NamedPipeSocketFactory 读 /proc/self/fd 上传的临时文件触发反序列化](web-java-deserialization-mysql-jdbc-namedpipe-proc-fd-no-egress.md) | verified | high | 2026-11-05 |
| [Nacos 配置中心写入 YAML 触发客户端 SnakeYAML 反序列化：ScriptEngineManager 加载远程 yaml-payload JAR 执行命令](web-java-deser-nacos-config-yaml-snakeyaml-yaml-payload-rce.md) | verified | high | 2026-11-12 |
| [nGrinder /github/validate 未授权 SnakeYAML loadAll 反序列化：!!ScriptEngineManager + URLClassLoader 加载远程 yaml-payload 执行命令](web-java-deser-ngrinder-github-validate-snakeyaml.md) | verified | medium | 2026-11-12 |
| [ObjectInputStream 漏拦 resolveProxyClass：动态代理 + Hutool MapProxy 二次反序列化绕过黑名单](web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy.md) | verified | high | 2026-11-06 |
| [OpenAM jato.clientSession 认证前反序列化：绕过 jato.pageSession 白名单的替代入口（CVE-2026-33439）](web-java-deserialization-openam-jato-clientsession-preauth-rce.md) | verified | medium | 2026-11-05 |
| [OpManager CVE-2023-31099：RegionalListener 白名单反序列化 DataObject，transferDataToNOC 在 notificationType=24 且 userProps 含 regReqID 时触发 getObjectData 二次反序列化 RCE](web-java-deserialization-opmanager-dataobject-regional-listener-getobjectdata-rce.md) | verified | high | 2026-11-12 |
| [Parquet Avro schema 指定 record 类经 SpecificData.newInstance 触发构造器 RCE（1.15.2 仍可绕过）](web-java-deserialization-parquet-avro-record-class-constructor-rce.md) | verified | high | 2026-11-05 |
| [Rhino1 反序列化链：BAVE→NativeError.toString→ScriptableObject.getProperty→NativeJavaMethod.call→NativeJavaObject.unwrap→MemberBox.invoke 任意方法](web-java-deser-rhino1-nativeerror-tostring-memberbox-invoke.md) | verified | high | 2026-11-10 |
| [ROME EqualsBean.equals/beanEquals 经 HashSet→AbstractMap.equals 触发 TemplatesImpl 字节码加载](web-java-deser-rome-equalsbean-beanequals-hashset-templatesimpl.md) | verified | high | 2026-11-12 |
| [ROME ToStringBean + BadAttributeValueExpException 反序列化触发 TemplatesImpl 字节码加载](web-java-deser-rome-badattribute-tostringbean-templatesimpl.md) | verified | high | 2026-11-12 |
| [ROME ToStringBean 反射 JdbcRowSetImpl.getDatabaseMetaData 触发 JNDI 注入（HashMap/ObjectBean 入口）](web-java-deser-rome-objectbean-jdbcrowset-jndi.md) | verified | high | 2026-11-12 |
| [Rome 原生反序列化链：HashMap→EqualsBean.hashCode→ToStringBean.toString 反射 getter→TemplatesImpl.getOutputProperties 加载字节码](web-java-deser-rome-equalsbean-tostringbean-templatesimpl.md) | verified | high | 2026-11-10 |
| [SerializedLambda 构造可序列化匿名类 + 多接口代理方法优先级：Hutool Singleton 到 Spring XML 加载](web-java-deser-serializedlambda-multiinterface-proxy-gadget.md) | verified | high | 2026-11-06 |
| [SerialKiller 白名单只放行 java.lang 与业务包：用业务动态代理触发 DriverManager.getConnection 打 MySQL autoDeserialize](web-java-deser-serialkiller-whitelist-business-proxy-mysql-autodeserialize.md) | verified | high | 2026-11-12 |
| [SerialKiller 类名黑名单下用 CC7 入口 + 单个 InvokerTransformer 调 RMIConnector.connect，借 /stub/ Base64 完成二次反序列化](web-java-deser-serialkiller-blacklist-cc7-invoker-rmiconnector-secondary.md) | verified | medium | 2026-11-08 |
| [shiro-redis RedisCache 缓存反序列化：拿到 Redis 口令后写 shiro:session 缓存投递 CommonsBeanutils1Shiro 载荷 RCE](web-java-deser-shiro-redis-cache-session-deserialization.md) | verified | high | 2026-11-13 |
| [SnakeYAML !<tag:yaml.org,2002:类名> 全写标签绕过 !! 过滤，触发 C3P0 userOverridesAsString 二次反序列化](web-java-deser-snakeyaml-full-tag-c3p0-useroverrides.md) | verified | medium | 2026-11-12 |
| [SolarWinds SEM BlazeDS AMF 反序列化入口：/messagebroker/streamingamf 未授权 POST 与 services-config 通配白名单绕过](web-java-component-solarwinds-sem-blazeds-amf-deserialization-wildcard-validator.md) | verified | high | 2026-11-11 |
| [Spring AOP AspectJAroundAdvice + PriorityQueue 代理链：反射调用 JdbcRowSetImpl.getDatabaseMetaData 打 JNDI，Overlong UTF-8 绕过 com.sun 字符串黑名单](web-java-deser-spring-aop-aspectjaroundadvice-priorityqueue-jndi.md) | verified | medium | 2026-11-07 |
| [Spring AOP MethodBeforeAdvice + PriorityQueue 比较器链：绕过危险类黑名单调用任意静态方法写 .so 并 System.load](web-java-deser-spring-aop-methodbeforeadvice-priorityqueue-arbitrary-method.md) | verified | high | 2026-11-06 |
| [Spring AOP 有参调用 gadget：AspectJAdvice + JdkDynamicAopProxy 经 Hashtable.equals 触发 Map.get](web-java-deserialization-spring-aop-parameterized-advice-gadget.md) | verified | high | 2026-11-05 |
| [Spring Boot SnakeYAML loadAs 黑名单双重 URL 编码绕过：JNDI 出网与 file:// 加载 multipart 临时 XML 无出网利用](web-java-deserialization-snakeyaml-loadas-blacklist-double-encode-file-xml.md) | verified | high | 2026-11-07 |
| [Spring MimeType 新反序列化入口类：readObject 调 getParameter → parameters.get 触发 LazyMap#get，接 CC1 链执行命令](web-java-deser-spring-mimetype-readobject-lazymap-cc1.md) | verified | high | 2026-11-10 |
| [Spring+Rome 原生链：HashMap.putVal→HotSwappableTargetSource.equals→XString.equals→ToStringBean.toString→TemplatesImpl 加载字节码](web-java-deser-rome-spring-hotswappable-xstring-tostringbean-templatesimpl.md) | verified | high | 2026-11-10 |
| [Spring-Kafka ErrorHandlingDeserializer 记录头反序列化 RCE（CVE-2023-34040）](web-java-deser-spring-kafka-errorhandlingdeserializer-header-cve-2023-34040.md) | verified | medium | 2026-11-11 |
| [sqlite-jdbc ::resource: 远程 URL 把攻击者文件落地到可预测 /tmp/sqlite-jdbc-tmp-hash.db，再借视图劫持 load_extension 加载该 .so](web-java-deserialization-sqlite-jdbc-resource-url-tmp-file-write.md) | verified | medium | 2026-11-07 |
| [sqlite-jdbc :resource 缓存落地恶意扩展 + 表名 UNION 注入 load_extension：CVE-2023-32697 完整 RCE 链](web-java-deserialization-sqlite-jdbc-resource-landing-union-load-extension-rce.md) | verified | high | 2026-11-08 |
| [sqlite-jdbc getTableContent 拼接 select * from <tableName>：可控表名注入 load_extension/ATTACH 执行任意 SQL 并加载扩展库 RCE](web-java-deserialization-sqlite-jdbc-table-name-select-injection-load-extension-rce.md) | verified | high | 2026-11-07 |
| [TarzanCMS 主题包 theme.yaml 触发 SnakeYAML 1.27 反序列化：ScriptEngineManager→URLClassLoader 远程加载 SPI 执行命令](web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce.md) | verified | high | 2026-11-05 |
| [TemplatesImpl 非 AbstractTranslet 载荷：构造/静态初始化在 ClassCastException 前执行](web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect.md) | verified | high | 2026-11-06 |
| [TemplatesImpl/ROME 链 payload 瘦身：Javassist 免编译生成 AbstractTranslet 字节码，省 _tfactory、_name 与容器 value 缩到 1 字符，Base64 从 2.8k 压到 1.3k](web-java-deserialization-templatesimpl-rome-javassist-payload-slimming.md) | verified | high | 2026-11-13 |
| [Vaadin AbstractSelect.getValue → SQLContainer.containsId → TableQuery.containsRowWithKey → J2EEConnectionPool.lookupDataSource 的原生反序列化 JNDI 链（TemplatesImpl 被禁时的替代 sink）](web-java-deser-vaadin-sqlcontainer-tablequery-connectionpool-jndi.md) | verified | medium | 2026-11-09 |
| [Vaadin NestedMethodProperty 调业务 bean getConnection：反序列化触发可控 JDBC URL，用伪 MySQL 服务端 LOCAL INFILE 读取目标本地文件](web-java-deser-vaadin-nestedmethodproperty-getconnection-fake-mysql-file-read.md) | verified | high | 2026-11-11 |
| [Vaadin PropertysetItem.toString → NestedMethodProperty.getValue 反射 getter 链：nested property 指向 TemplatesImpl.outputProperties 直接触发 translet 加载](web-java-deser-vaadin-propertysetitem-nestedmethodproperty-templatesimpl.md) | verified | high | 2026-11-09 |
| [ysoserial Groovy1 原生反序列化链：AnnotationInvocationHandler.readObject 触发 Map 代理，ConvertedClosure→MethodClosure→String.execute 命令执行](web-java-deser-groovy1-annotationinvocationhandler-convertedclosure-methodclosure.md) | verified | high | 2026-11-12 |
| [ysoserial Spring1/Spring2：MethodInvokeTypeProvider.readObject 入口经三层动态代理到 TemplatesImpl.newTransformer 的 Spring 反序列化链](web-java-deser-yso-spring1-spring2-methodinvoketypeprovider-templatesimpl.md) | verified | high | 2026-11-08 |
| [ZipEntry 路径穿越覆盖 classpath 类文件 + 原生反序列化：上传恶意 Serializable 类后发送其实例触发 readObject 命令执行](web-java-deser-zipentry-class-overwrite-readobject-rce.md) | verified | medium | 2026-11-10 |
| [「任意 getter → newInstance」新 sink：jOOQ ConvertedVal.getValue 经 Convert.convert 反射调用 ClassPathXmlApplicationContext 单参构造，加载远程 XML；用 EventListenerList→toString→POJONode 把任意 getter 接进反序列化链](web-java-deser-any-getter-jooq-convert-newinstance-spring-xml.md) | verified | medium | 2026-11-08 |
| [仅允许 HashMap 的反序列化接口被业务字段滥用：path 直达 FileInputStream 任意文件读取](web-java-deserialization-hashmap-business-field-local-file-read.md) | verified | high | 2026-11-05 |
| [内网自研 Java 服务 socket 流直接 readObject：ysoserial CC6 生成 .ser 经 nc 管道直发端口 RCE](web-java-deser-socket-objectinputstream-ysoserial-nc.md) | verified | high | 2026-11-13 |
| [冷门 JDBC 驱动自带的“连接即攻击”入口：ModeShape 的 jdbc:jcr:jndi 直接 lookup，Derby 的 startMaster/slaveHost 把复制流当序列化流读取](web-java-deserialization-jdbc-driver-jndi-derby-replication-jcr-modeshape.md) | verified | medium | 2026-11-09 |
| [反序列化 Getter 链触发 H2 JDBC URL INIT 参数命令执行](web-java-deserialization-h2-jdbc-init-create-alias-rce.md) | verified | medium | 2026-11-05 |
| [反序列化 payload 长度受限时用 TemplatesImpl 轻量 stub 经 request 参数 defineClass 二次加载内存马](web-java-deserialization-templatesimpl-stub-param-defineclass-secondload.md) | verified | high | 2026-11-08 |
| [反序列化 TemplatesImpl 静态块经 ApplicationFilterChain.lastServicedRequest 获取 request，注入 Tomcat Filter 内存马（翻转 WRAP_SAME_OBJECT，两步触发）](web-java-deserialization-templatesimpl-lastservicedrequest-filter-memshell.md) | verified | high | 2026-11-13 |
| [反序列化 toString 触发 SCXML 远程加载：SimpleSCXMLInvoker.invoke 把 source 交给 SCXMLReader.read(new URL())，JexlEvaluator 执行 <script> 内任意代码](web-java-deserialization-tostring-scxml-remote-url-jexl-script-rce.md) | verified | medium | 2026-11-09 |
| [只可控 dbname 时的 JDBC URL 参数走私：把 query 串拼进库名覆盖 Properties 里的 allowLoadLocalInfile=false，走恶意 MySQL 服务端 autoDeserialize 反序列化](web-java-deserialization-jdbc-dbname-url-param-smuggling-autodeserialize.md) | verified | high | 2026-11-08 |
| [后台的「数据库连接测试」页面把 URL/用户名/密码全部交给用户填：审计时按 type 分支找到 DriverManager.getConnection 入口，用伪 MySQL 服务端 + yso gadget 命名在用户名里回打反序列化](web-java-deserialization-db-connection-test-page-jdbc-url-controlled.md) | verified | medium | 2026-11-08 |
| [命令字符串被服务端自己拼成 XMLDecoder 的 Bean XML：用户不提供 XML 也能经 ProcessBuilder.start 执行命令，修复只能换解析器（SAX/JAXB）而非加白名单](web-java-deserialization-xmldecoder-server-built-xml-processbuilder.md) | verified | medium | 2026-11-09 |
| [帆软 /remote/design/channel Gzip+SafeInvocationSerializer 反序列化：V10 前台、V11 后台触发](web-java-deserialization-finereport-channel-gzip-safeinvocation.md) | verified | medium | 2026-11-05 |
| [帆软反序列化绕黑名单：Hashtable/TextAndMnemonicHashMap 触发 JSONArray→Druid→HSQL 二次反序列化 RCE](web-java-deserialization-finereport-hashtable-textandmnemonic-jsonarray-druid-hsql.md) | verified | high | 2026-11-07 |
| [序列化端生成 UTF-8 Overlong Encoding：Java Agent + Javassist 重写 ObjectOutputStream$BlockDataOutputStream#writeUTF/writeUTFBody，让类名自动三字节编码绕过字节黑名单](web-java-deser-overlong-utf8-javaagent-writeutf.md) | verified | medium | 2026-11-10 |
| [应用自带 readObject 把字段喂给 HashMap.put：借 aspectjweaver StoreableCachingMap 把可控 put 变成任意路径文件写，落 class 后再反序列化同名校触发类加载执行](web-java-deserialization-app-readobject-controlled-put-aspectj-file-write.md) | verified | medium | 2026-11-07 |
| [恶意 MySQL 服务端在结果列里回吐 SignedObject 嵌套流：驱动侧 readObject 被类黑名单限制时，用 Jackson POJONode getter 触发 SignedObject.getObject 完成二次反序列化](web-java-deserialization-fake-mysql-signedobject-jackson-second-order-bypass.md) | verified | medium | 2026-11-09 |
| [恶意 MySQL 服务端承接自定义序列化 payload：按 user 值选链的 GadgetResolver 遇目标硬编码 user 失效需改识别键，且 payload 文件尾随换行会让 Base64 解码整体错位](web-java-deserialization-fake-mysql-custom-gadget-user-key-newline.md) | verified | high | 2026-11-08 |
| [手写恶意 MySQL 服务端：greeting 固定字节 + 必回 SHOW WARNINGS + BLOB 列，才能让驱动把结果集当对象反序列化](web-java-deserialization-fake-mysql-server-protocol-greeting-warnings-blob.md) | verified | medium | 2026-11-09 |
| [接口动态代理包装 TemplatesImpl 绕过 Jackson/Fastjson 黑名单与 JDK17 模块封装](web-java-deserialization-interface-proxy-templatesimpl-blacklist-bypass.md) | verified | high | 2026-11-05 |
| [接收任意 Serializable 对象且业务类 readObject 直接 Runtime.exec 导致反序列化 RCE](web-java-deserialization-custom-readobject-runtime-exec.md) | verified | high | 2026-11-05 |
| [无出网反序列化组合链：BAVE/TreeMap/BeanComparator 触发 getConnection，PgJDBC loggerFile 写 FreeMarker 模板后 SSTI](web-java-deser-noegress-pgjdbc-loggerfile-freemarker-ssti.md) | verified | high | 2026-11-12 |
| [普元 EOS ControllerServlet 的 _eosFlowDataContext 参数 Base64 原生反序列化](web-java-deser-eos-flowdatacontext-deserialize.md) | verified | high | 2026-11-12 |
| [构造反序列化 payload 时用 Java Agent + Javassist 删除 CertPath.writeReplace：避免序列化被 CertPathRep 替换导致链中断](web-java-deser-certpath-writereplace-agent-strip.md) | verified | medium | 2026-11-10 |
| [某软 BI v5 反序列化绕黑名单：Hashtable/TextAndMnemonic→JSONArray→Jackson getter→OracleCachedRowSet JNDI（LDAP javaSerializedData）](web-java-deserialization-finebi-v5-jsonarray-jackson-oracle-rowset-jndi.md) | verified | high | 2026-11-08 |
| [特殊反序列化组件作 toString 桥的 sink 兼容性：TemplatesImpl 三组件通用、JdbcRowSetImpl 仅 ROME、LdapAttribute 排除 ROME](web-java-deser-special-component-tostring-bridge-sink-compatibility.md) | verified | high | 2026-11-13 |
| [用友 NC UserSynchronizationServlet 未认证 readObject 入口：/servlet/~uapim 路由叠加 CC6 链 RCE](web-java-deser-yonyou-nc-usersynchronizationservlet.md) | verified | high | 2026-11-05 |
| [用友 ZiOR ActionHandlerServlet 反序列化后反射调度任意方法：ActionExecutor.exec 按类名/方法名/参数直接反射调用](web-java-deserialization-ufida-zior-actionexecutor-reflection.md) | verified | high | 2026-11-09 |
| [直接可控 JDBC URL 加 autoDeserialize：恶意 MySQL 服务端返回序列化对象 RCE](web-java-deserialization-mysql-jdbc-url-autodeserialize-rce.md) | verified | high | 2026-11-05 |
| [自定义 Java 二进制 RPC 的序列化端点探测：Integer 长度前缀协议与 ResponseMessage 异常栈回显](web-java-deser-custom-length-prefix-serialization-endpoint-discovery.md) | verified | high | 2026-11-13 |
| [自定义 readObject 反射调用 + RMIConnector 二次反序列化绕过黑名单](web-java-deser-readobject-reflection-rmiconnector-secondary.md) | verified | medium | 2026-11-05 |
| [通天星 CMSV6 StandardLineAction_report 的 name 控制 .jasper 路径：JRLoader.loadObject 反序列化 RCE（读日志取 session + 默认 FTP 上传组合链）](web-java-deserialization-cmsv6-standardline-report-jasper-jrloader.md) | verified | medium | 2026-11-08 |
| [黑名单同时封禁 BAVE/TemplatesImpl 的 Jackson 组合链：HotSwappableTargetSource+XString 触发 POJONode(SignedObject)，内层裸流反序列化 BAVE(POJONode(AOP TemplatesImpl))](web-java-deser-hsts-xstring-pojonode-signedobject-inner-bave-templatesimpl.md) | verified | medium | 2026-11-12 |
| [黑名单封禁 javax.swing/java.security 后的 JDK17 Spring 链：HotSwappableTargetSource+XString 接 POJONode/TemplatesImpl](web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
