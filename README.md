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

# py-xiaozhi-m1
**万分感谢原作者的贡献**

## 修改点
1. 使用3.11.xx版本的python
2. 使用1.7.6版本的pynput
3. 修改py-xiaozhi.py文件中的sent = udp_socket.sendto(data, (server_ip, server_port)) 为sent = udp_socket.send(data)

## 操作步骤
1. 创建虚拟环境
   python3.11 -m venv py-xiaozhi3.11
2. 激活虚拟环境
   source py-xiaozhi3.11/bin/activate
3. 安装依赖
   pip3  install -r requirements.txt
4. 运行脚本
   python3 py-xiaozhi.py