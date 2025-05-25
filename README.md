# API越权漏洞检测工具

## 概述

请将代码内容放在**D:IDOR**下
下载好conda以后，命令行运行以下内容
conda create --name idor python=3.8
D:
cd D:\IDOR
conda activate idor
mitmdump -s test.py -p 8080


在操作系统->控制面板->代理服务器中，开启代理，端口号8080
开启网页，观察命令行情况

进展250524：**现在只能用于检测并筛出请求，还没有对请求进行处理**
