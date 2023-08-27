# preprocess-middleware

为Traefik网关开发的一个请求预处理中间件插件

## 功能

- 进行JWT解码：也就是说如果`header`字段`Authorization`中包含`Bearer token`则进行解码验证，验证错误并不响应错误，验证成功则传递给后面真正的服务。只有后面的业务服务才有权限控制是否需要认证。
- 获取会话信息：如果cookie中包含会话ID（字段`sid`），则需要携带会话id向认证服务发起请求，然后将获取的会话信息传递给后面的接口，同样的获取成功或者失败都传递给后面的业务服务，不干预响应。

## 使用

> 主要介绍在本地开发模式下的使用

如果在docker中启动Traefik，我们需要将插件放在`/plugins-local`目录下，例如：

```yaml
version: '3'

services:
  reverse-proxy:
    image: traefik
    ports:
      - "8090:80"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./conf:/etc/traefik
      - /Users/jqs/Desktop/Projects/BlackSwanXDU/req-preprocess:/plugins-local/src/github.com/SwanHubX/req-preprocess
```

> 则插件挂载到容器中的`/plugins-local/src/github.com/SwanHubX/req-preprocess`下
>
> 注意路径应该安装插件配置文件`.traefik.yml`的`import`字段定义

在Traefik配置中引入插件：

```yaml
experimental:
  localPlugins:
    rpp:
      moduleName: github.com/SwanHubX/req-preprocess
```

然后就可以设置中间件：

```yaml
http:
  routers:
    my-router:
      rule: "PathPrefix(`/api`)"
      service: test
      priority: 0
      middlewares:
        - "preprocess"
  services:
    test:
      loadBalancer:
        servers:
          - url: "http://host.docker.internal:3000/"
  middlewares:
    preprocess:
      plugin: 
        rpp:
          AuthUrl: "http://host.docker.internal:3000/api/auth"
          Key: |
          	-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA61/d80yCyzy70PtWcslU
            ezWOu02Q6GbtUesCD6mnSiBeocbQGdXejvLRbSrwA8DXyRX8fvg5TPUCFCUza8DW
            J995UhsyIjg6w9ubNA7LbddUDLfREs7pBP7lcjU0LG17LAm9vdusgF6wb7UgGctA
            201uiJ+NilHgf94QaSqtwjaAw6maIdACllxUMj4ZW/4lfJc6pm8YDyOVM5+eE+jE
            yiPoLhkMuROvY9SONe0oMZRnj2O2fwjEPzwXMaWnTF7Em2cJaysgnnDA4dcxa64a
            b1imJPMYq+AAulbAdIiz6YZoUNT12M/zgBgBJcsur4Ss5xFceJMB1N12cjfqA+S3
            7QIDAQAB
            -----END PUBLIC KEY-----

```

## 配置

| Key     | 说明    |
| ------- | ------- |
| AuthUrl | 认证URL |
| Key     | JWT公钥 |

## Q&A

### 1. 为什么不直接在插件中访问Redis

获取会话信息实际上就是在Redis数据库中检索对应会话id的值然后传递给后面的接口，在插件中直接访问Redis似乎路径更短。

刚开始确实是这么考虑的，但是逐渐发现有一些问题。连接Redis是有一个连接池的，如果每次请求都发起一个连接对性能影响是很大的，但是不太明白在插件中如何初始化并保留连接。而且就算可以保留连接，连接断开后重连也是一个很难处理的问题。同时编写一个单独的接口还能记录查询日志。

