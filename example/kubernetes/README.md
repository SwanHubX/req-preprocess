该Service配置指向的服务为集群外部的服务，用于验证。有两个关键的资源如下，代表指向 `192.168.16.17:8090` 的外部服务：
```yml
apiVersion: v1
kind: Service
metadata:
  name: controller
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 8090
---
apiVersion: v1
kind: Endpoints
metadata:
  name: controller
subsets:
  - addresses:
      - ip: 192.168.16.17
    ports:
      - port: 8090
```
> 注意 Middleware 中的定义方式