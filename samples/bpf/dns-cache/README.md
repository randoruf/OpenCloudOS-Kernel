# DNS cache方案

## 一，背景
弹性容器服务（Elastic Kubernetes Service，EKS）是腾讯云容器服务推出的无须用户购买节点即可部署工作负载的服务模式。该模式下，直接售卖给客户的是集群中的POD，用户是接触不到POD所在的节点的。
在拥有大量POD的节点上，对于dns的处理通常有2种情况：

1，如果不配置dns代理，那么所有的dns请求都会抵达上游dns服务器，给上游服务器造成巨大压力，从而产生性能问题。

2，如果配置dns代理，那么传统的模式是增加一个dns-pod来专门作为dns代理服务器使用，这虽然能够减轻上游dns服务器压力，但是牺牲了节点内的资源，并且用户容易忘记配置，从而导致了诸多不便。

该方案使得用户无需配置dns-pod，不仅性能优于dns-pod，并且还节省资源，有着开箱即用的优点。

## 二，方案设计
dns-cache是工作在tc层的ebpf程序，它在tc的egress和ingress上面都有hook节点。

1，dns-cache程序会在egress上面抓取目的端口为53的dns请求报文，并将dns请求报文作为hash key，去内部维护的hash表中查询是否有对应的dns应答报文，如果有，则将该应答报文返回给请求方，并丢弃当前请求报文；如果没有，则放行当前dns请求报文。

2，dns-cache程序会在ingress上面抓取源端口为53的dns应答报文，并将应答报文的请求头部作为hash key，同时将应答报文的应答数据当成hash value存入到内部维护的hash表当中，然后放行该应答报文（不会丢弃）。

3，dns-cache程序在发现有dns缓存的时候，会通过读取dns缓存数据内部的ttl字段，来判断当前dns缓存是否过期，如果缓存过期了，则直接放行当前dns请求；如果没有过期，则丢弃当前dns请求，然后将该dns应答给请求方。

4，dns-cache程序提供一套统计数据，用于统计不同情况下的数据包个数，可以通过bpftool map导出来分析。

## 三，使用方法

```
$./dns-cache 
usage: dns-cache [OPTS] IFACE

OPTS:
    -m N         设置最大dns缓存数量
    -l N         设置ulimit限制，默认是ulimited，单位KBytes
    -i           设置dns隔离
    -h           帮助
```
使用示例：

```
$./dns-cache -i eth1
```
指定dns-cache工作在eth1接口上面，并且工作在dns服务器隔离的模式下（dns隔离是指区分不同dns服务器的相同dns请求）。


## 四，待改进

1，目前dns-cache不支持dns附加报文。

2，目前dns-cache不支持多query数量的报文。


注：可以通过修改dns.map.h中的CACHE_KEY_LEN和CACHE_VALUE_LEN修改默认的DNS缓存，当然默认值是500和1000。

