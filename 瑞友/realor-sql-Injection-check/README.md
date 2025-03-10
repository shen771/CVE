# realor-sql-Injection-check
瑞友天翼应用虚拟化系统远程代码执行漏洞检测工具

## 来源

[https://github.com/Okaytc/realor-sql-Injection-check](https://github.com/Okaytc/realor-sql-Injection-check)

## 简介

  瑞友天翼应用虚拟化系统存在远程代码执行漏洞，未经身份认证的远程攻击者可以利用该漏洞在目标系统上执行任意代码，（该漏洞是通过[SQL注入](https://so.csdn.net/so/search?q=SQL注入&spm=1001.2101.3001.7020)写入后门文件进行代码执行）

## 影响范围

 5.x <= 瑞友天翼应用虚拟化系统 <= 7.0.2.1


**本工具仅用于教育和研究目的，以提高安全意识和改进软件开发实践。在使用本工具之前，请确保您遵守了相关法律法规和道德准则。**

开发环境： python3

```python
使用方式（支持单个URL检测和批量检测）：//url做了合规处理，支持输入ip、ip:port样式

单个检测：python realor-sql-Injection-check.py -u

示例：python realor-sql-Injection-check.py -u http://192.168.1.1/

批量检测：python realor-sql-Injection-check.py -f

示例：python realor-sql-Injection-check.py -f url.txt
```

演示截图：

单个检测：

![图片](https://user-images.githubusercontent.com/50813688/232356970-3366a60f-7950-4fe1-b526-8e36fc2fa6f1.png)

批量检测:

![图片](https://user-images.githubusercontent.com/50813688/232357328-d8b31fa7-90ab-4b52-add1-028f904e1115.png)
