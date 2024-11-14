<h1 align="center">
  <b>VscanPlus</b>
  <br>
</h1>
<p align="center">二次开发版本的vscan，开源、轻量、快速、跨平台 的网站漏洞扫描工具，帮助您快速检测网站安全隐患。</p>

<p align="center">
<a href="https://github.com/youki992/VscanPlus/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/youki992/VscanPlus"><img alt="Release" src="https://img.shields.io/badge/LICENSE-BSD-important"></a>
<a href="https://github.com/youki992/VscanPlus/releases"><img src="https://img.shields.io/github/release/youki992/VscanPlus"></a>
<a href="https://github.com/youki992/VscanPlus/releases"><img src="https://img.shields.io/github/downloads/youki992/VscanPlus/total?color=blueviolet"></a>
</p>

<p align="center">
  <a href="/static/Installation.md">编译/安装/运行</a> •
  <a href="/static/usage.md">参数说明</a> •
  <a href="/static/running.md">使用方法</a> •
</p>

# Features

![image](./static/help.png)

![image](./static/exp.png)

# Updates

- ehole指纹更新
- nuclei检测脚本更新
- xray检测脚本更新
- 支持xray yml v2语法
- 修复nuclei模板读取缺失字段报错
- 规范指纹名称，nuclei、xray检测脚本命名格式

# Commits

- 根据原vscan开发文档，用户可以自定义指纹和poc，两者的调用关系是：先检测指纹，再调用对应poc，类似于nuclei前不久更新的-ac命令行的检测功能，都是基于指纹来检测漏洞

<div style="text-align: center;">
    <img src="static/fingerprint.png" alt="vscan" style="width: 850; display: block; margin: 0 auto;">
</div>

- 根据原vscan开发文档，指纹对应的xray poc命名格式为：指纹-xxxx-yml，因此对新增的poc进行了格式统一，包括：
``
泛微oa 
用友oa
通达oa
金和oa
thinphp
spring-boot
springblade
apache-tomcat
drupal
microsoft-exchange
sangfor
其他HW热门漏洞
``

- nuclei则是通过tags加载poc

<div style="text-align: center;">
    <img src="static/nuclei.png" alt="vscan" style="width: 850; display: block; margin: 0 auto;">
</div>

- ~~在原vscan的xray规则检测基础上，使用类似nuclei加载template的逻辑重写了yml v2的多规则检测，可以实现多表达式的检测功能~~

- 新增子域名接管漏洞模糊检测功能

  主要参考了https://github.com/EdOverflow/can-i-take-over-xyz项目中的检测规则，通过对比域名cname解析以及请求返回信息，判断对应域名是否存在子域名接管漏洞。检测完成后，会在当前目录下生成matched_domains.txt文件

![image](https://img.picui.cn/free/2024/11/14/67356bc8eff9e.png)

# Todo

- 待修复部分检测脚本加载失败bug

# Warning

- 如需编译生成可执行文件，请下载release中的vcsanplus-main-code.zip文件编译

# Reference

https://github.com/veo/vscan

# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=youki992/VscanPlus&type=Date)](https://star-history.com/#youki992/VscanPlus&Date)
