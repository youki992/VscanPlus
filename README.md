<h1 align="center">
  <b>VscanPlus</b>
  <br>
</h1>
<p align="center">VscanPlus is a second development version of Vscan, an open-source, lightweight, fast, cross-platform website vulnerability scanning tool that helps you quickly detect website security vulnerabilities.</p>

<p align="center">
<a href="https://github.com/youki992/VscanPlus/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/youki992/VscanPlus"><img alt="Release" src="https://img.shields.io/badge/LICENSE-BSD-important"></a>
<a href="https://github.com/youki992/VscanPlus/releases"><img src="https://img.shields.io/github/release/youki992/VscanPlus"></a>
<a href="https://github.com/youki992/VscanPlus/releases"><img src="https://img.shields.io/github/downloads/youki992/VscanPlus/total?color=blueviolet"></a>
</p>

<p align="center">
  <a href="/README_zh.md">中文文档</a> •
  <a href="/static/Installation.md">Compilation/Installation/Running</a> •
  <a href="/static/usage.md">Parameter Description</a> •
  <a href="/static/running.md">Usage</a> •
</p>

# Features

![image](./static/help.png)

![image](./static/exp.png)

# Updates

- Updated ehole fingerprint
- Updated nuclei detection scripts
- Updated xray detection scripts
- Fixed missing field error when reading nuclei templates
- Standardized fingerprint names, nuclei, xray detection script naming format

# Commits

- According to the original vscan development documentation, users can customize fingerprints and pocs. The calling relationship between the two is: first detect the fingerprint, then call the corresponding poc, similar to the recently updated -ac command line detection feature in nuclei, both based on fingerprints to detect vulnerabilities

<div style="text-align: center;">
    <img src="static/fingerprint.png" alt="vscan" style="width: 850; display: block; margin: 0 auto;">
</div>

- According to the original vscan development documentation, the xray poc naming format corresponding to the fingerprint is: fingerprint-xxxx-yml, so the format of the newly added pocs has been standardized, including:
``
Weaver-OA
Yonyou-OA
Tongda-OA
Jinhe-OA
ThinPHP
Spring-Boot
Spring-Blade
Apache-Tomcat
Drupal
Microsoft-Exchange
Sangfor
``

- Nuclei loads pocs through tags

<div style="text-align: center;">
    <img src="static/nuclei.png" alt="vscan" style="width: 850; display: block; margin: 0 auto;">
</div>

- ~~Based on the xray rule detection of the original vscan, the logic of loading multiple rules in yml v2 similar to nuclei templates has been rewritten, which can achieve multi-expression detection functionality~~

# Todo

- Fix bugs related to some detection scripts failing to load

# Warning

- To compile and generate executable files, please download the vcsanplus-main-code.zip file from the releases

**本工具由Code4th安全团队二次开发和维护**

![image](https://ice.frostsky.com/2024/08/18/5559fc7abc47065e9e5e53a7dba2142b.jpeg)

**团队公开群**
- QQ群一群（772375860）

**团队内部知识大陆**

![image](https://ice.frostsky.com/2024/08/18/bea40903e13c5ae238926338dd3b5331.png)

# Reference

https://github.com/veo/vscan

# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=youki992/VscanPlus&type=Date)](https://star-history.com/#youki992/VscanPlus&Date)
