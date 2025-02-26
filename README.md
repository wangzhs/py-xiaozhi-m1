# py-xiaozhi
***用python实现的小智客户端***,用于代码学习和在没有硬件条件下体验AI小智的语音功能</br>
* 厡项目作者地址[xiaozhi-esp32](https://github.com/78/xiaozhi-esp32)</br>
* [***bilibili演示视频***](https://b23.tv/GbXeLHX)</br>
* **注意需要手动修改脚本中的全局变量MAC_ADDR**,以区分不同的客户端</br>
* **按住空格键发起对话**

**测试使用的python 版本为3.12(其它python3应该也可以,没做测试)**

## windows需要安装依赖
* pip 安装依赖模块
pip3  install -r requirements.txt
* 将opus.dll拷贝到至C:\Windows\System32目录中

## 启动命令
```python
python py-xiaozhi.py
```
