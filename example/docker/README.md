该目录下提供了使用 `docker compose` 运行的案例。

Traefik 配置我们分为静态配置和动态配置两部分，`./conf/traefik.yml` 为静态配置，其中定义了基础配置以及插件的路径和名称。所有的动态配置都放置在 `./conf/dynamic` 目录下，其中给出了一个示例文件 `whoami.yml` 。

在使用 `docker compose` 运行前需要将最新的插件目录放置在 `./plugins` 目录下并命名为：`req-preprocess`。

网关的入口映射到本机 `8090` 端口，Traefik 控制台界面映射到本机 `8080` 端口

