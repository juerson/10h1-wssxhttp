# 10h1-wssxhttp

十合一部署代码，含ws和xhttp两大传输协议。

### 一、支持协议：

| 协议        | ws（WebSocket） | xhttp（GRPC over HTTP2） |
| ----------- | --------------- | ------------------------ |
| VLESS       | ✅               | ✅                        |
| Trojan      | ✅               | ✅                        |
| Shadowsocks（无加密） | ✅               | ✅                        |
| Shadowsocks（有加密） | ✅               | ✅                        |
| VMess       | ✅               | ✅                        |

Shadowsocks（有加密），可以选择以下加密方式之一：

| 加密方式 | 协议版本 | 状态 | 执行命令生成密码 |
|---------|---------|------|---------|
| 2022-blake3-aes-128-gcm | SS2022 | ✅ | openssl rand -base64 16 |
| 2022-blake3-aes-256-gcm | SS2022 | ✅ | openssl rand -base64 32 |
| 2022-blake3-chacha20-poly1305 | SS2022 | ✅ | openssl rand -base64 32 |
| aes-128-gcm | AEAD2017 | ✅ |  |
| aes-256-gcm | AEAD2017 | ✅ |  |
| chacha20-ietf-poly1305 | AEAD2017 | ✅ |  |

使用 Git Bash 自带 OpenSSL，直接打开 Git Bash 运行：

```bash
openssl rand -base64 16
openssl rand -base64 32
```

注意：xhttp需要自备域名，且开启gRPC。

## 二、本地部署

将全部代码下载/`git clone`拉取到本地电脑，然后根据下面方法部署。

- 1、准备具备`rust` + `wasm32-unknown-unknown` + `wrangler`的开发环境，以及会编译它的基础能力（必须，这步骤不能做到，就不要本地部署，研究其它部署方法，或者放弃部署它）

- 2、切换到该代码的根目录，执行下面的命令编译，为部署到worker中准备：

  ```
  cargo install worker-build && worker-build --release
  ```

  编译成功，会在根目录生成"/build/"文件夹，文件夹里面包括一堆所需部署的文件，不用管它，后面使用 `wrangler deploy` 命令会自动上传代码部署的。

- 3、修改 **wrangler.toml** 配置参数

  - name 参数修改，修改worker项目名称，改为不那么敏感的名称。
  
  - KV => ID，（重点修改）需要你先到cf后台创建一个名为`mykv`的KV空间（不能改其它名字），得到一个ID字符串。
  - vars 参数（选择性修改，一些参数可以在CF网站后台中修改）
  
- 4、运行下面命令，正式部署到 cf workers 中。

  ```cmd
  wrangler login
  wrangler deploy
  ```

 （简洁总结）依次执行下面命令：

  ```cmd
  # 编译
  cargo install worker-build && worker-build --release
  # 登录
  wrangler login
  # 部署
  wrangler deploy
  ```

## 三、免责声明

该项目仅供学习/研究目的，用户对法律合规和道德行为负责，作者对任何滥用行为概不负责。

## 四、感谢

代码基于 https://github.com/FoolVPN-ID/Siren 修改。

