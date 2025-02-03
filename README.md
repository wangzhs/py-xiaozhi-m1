# py-xiaozhi
***用python实现的小智客户端***,用于代码学些和在没有硬件条件下体验AI小智的语音功能</br>
厡项目作者地址[xiaozhi-esp32](https://github.com/78/xiaozhi-esp32)

## windows需要安装依赖
* pip 安装 pyaudio paho pyaudio keyboard opuslib
* 将libopus_win32_x64.zip解压至C:\Windows\System32目录中
* 找到opuslib包的__init__.py文件，做如下修改
```sh\
lib_location = find_library('libopus')
```