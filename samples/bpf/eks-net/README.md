# EKS网络方案

## 一、背景

弹性容器服务（Elastic Kubernetes Service，EKS）是腾讯云容器服务推出的无须用户购买节点即可部署工作负载的服务模式。该模式下，直接售卖给客户的是集群中的POD，用户是接触不到POD所在的节点的。该方式使得用户无需直接维护、管理节点资源，有着开箱即用的优点。

由于多个用户的POD运行在同一个节点上，可能会引发资源隔离不充分的问题。因此，为了提高POD的隔离性，EKS在设计时采用了轻量级虚拟化的方案，即每个CVM节点里只运行一个POD，结构如下图所示：

<img src="images/image-20220531141724671.png" alt="image-20220531141724671" style="zoom: 67%;" />

POD和节点通过命名空间来隔离，其中POD暴露给用户，称为业务面；节点对用户不可见，称为管理面。每个节点有个对外的主网口eth0，基于eth0创建了两个ipvlan虚拟网口ipvlan1和ipvlan2，分别给管理面和业务面使用。为了节省IP地址，整个节点只分配一个对外的IP地址（主IP）并配置在ipvlan2上给业务面使用。管理面的ipvlan1上也会配置一个IP（从IP），该IP仅用于节点访问当前POD，节点的业务面在访问外部网络时需要使用主IP（即配置在ipvlan2上的IP）。在这种网络结构中，POD访问网络不需要进行额外的操作，但是管理面的流量需要经过NAT，且需要保证管理面和数据面不产生冲突。

原先的EKS的网络转发方案是基于eBPF做的NAT，详情可见[这里](https://iwiki.woa.com/pages/viewpage.action?pageId=1041811089)。其转发逻辑如下图所示，核心思想为：（1）创建一个MAP来在发包阶段跟踪、保存控制面的TCP连接，并进行SNAT；（2）收包阶段如果在MAP中找到对应的连接，就进行DNAT。同时，需要预留一定的端口范围给控制面使用（如控制面需要进行端口监听等）。

<img src="images/image-20220531151933317.png" alt="image-20220531151933317" style="zoom:50%;" />

该方案存在一定的弊端，即预留给控制面的端口管理面不能使用，使用了的话报文会直接转发到控制面，从而导致数据传输异常。而告知、管理客户不能使用哪些端口又比较困难，因此需要一种更加灵活的方式来避免这种冲突。

## 二、方案设计

### 2.1 总体要求

从上文中可以看出，本方案要满足的要求包括：

- 不进行端口预留，而是动态检查控制面的端口使用，即只转发有效的报文到控制面
- 冲突上报，即在控制面和管理面发生端口使用冲突时，需要终止后一方端口的使用，即`connect()`或者`listen()`需要失败并返回一定的错误码，从而在早期（业务部署阶段）发现不可避免的端口冲突并进行解决。

### 2.2 方案设计

从功能上，方案可以分为三部分，包括：冲突检查、报文转发和连接跟踪；从开发上，方案分为两部分，包括：用户态eBPF程序编写和内核eBPF类型修改/新增。

#### 2.2.1 冲突检查

下面以业务面的TCP数据传输为例来说明本方案的冲突检查机制（控制面的类似）。针对TCP协议，这里维护了四个哈希表，分别是用于业务侧的已建链表（四元组表示）`ehash`、处于listen状态的端口的`lhash`；管理侧的已建链表（四元组表示）`ehash`、处于listen状态的端口的`lhash`。

![image-20220531161103436](images/image-20220531161103436.png)

TCP连接冲突检查有两个地方，分别是`connect()`和`listen()`。listen的检查逻辑比较简单，`sockops`类型的eBPF程序会被调用来检查要使用的端口是否已经被控制面使用（listen）。如果已经被使用的话，eBPF程序通过返回`SOCK_OPS_RET_REJECT`来阻止`listen()`系统调用的进行，导致系统调用失败并返回`EPERM`错误。由于业务面和管理面不能同时监听同一个端口，因此该冲突无法避免。需要注意的是，同一个端口可能被listen多次（开启端口复用），因此lhash表里存放的是个引用计数，即该端口已经被当前业务listen了多少次，在归0的时候会将对应的数据实例释放。

`connect()`的时候要保证四元组不冲突，因此需要根据四元组检查管理侧的`ehash`表中是否存在该连接，如果存在的话就返回失败。该过程也是通过`sockops`类型的eBPF程序来实现的。而`connect()`所使用的的端口分为两种情况：主动绑定和随机分配（主要情况）。对于随机分配的端口，由于控制面和管理面已经通过`/proc/sys/net/ipv4/ip_local_port_range`来进行隔离，因此不会产生冲突。

<img src="images/image-20220531155339232.png" alt="image-20220531155339232" style="zoom: 50%;" />

#### 2.2.2 报文转发

报文转发的逻辑比较简单。对于出向TCP流量，如果源地址为`slaveip`，那么将其改为`masterip`。对于入向流量，转发逻辑为：

1. 如果其四元组存在于管理侧的`ehash`表中，那么将其目的地址改为`slaveip`
2. 如果四元组存在于业务面的`ehash`表中，那么不做操作
3. 如果目的端口存在于管理侧的`lhash`中，那么修改其目的地址为`slaveip`

#### 2.2.3 连接跟踪

对于TCP协议，连接的跟踪可以通过`sockops`类型的eBPF程序来实现，该类型的eBPF会在TCP套接口生命周期的各个地方被调用，并将当前的`op`（操作类型）传递给eBPF程序。本方案所使用的到的op包括：

- `BPF_SOCK_OPS_TCP_CONNECT_CB`：主动建立TCP连接（即使用`connect()`系统调用）。在该处进行冲突检查，并在冲突检查通过后，将四元组添加到对应的`ehash`表中
- `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`：被动建立TCP连接（即本端作为服务端接收对端建立的连接）。在该处进行冲突检查，并在冲突检查通过后，将四元组添加到对应的`ehash`表中
- `BPF_SOCK_OPS_TCP_LISTEN_CB`：端口监听（使用`listen()`系统调用）。在该处进行冲突检查，并在冲突检查通过后，将四元组添加到对应的`lhash`表中
- `BPF_SOCK_OPS_STATE_CB`：TCP套接口状态发送变化。在套接口进入到`close`状态时，将对应的数据从`lhash`或者`ehash`中移除。

#### 2.2.4 内核修改

1. `BPF_SOCK_OPS_TCP_CONNECT_CB`、`BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`和`BPF_SOCK_OPS_TCP_LISTEN_CB`的返回值在内核中没有被使用，因此无法通过eBPF程序的返回值来阻止操作的进行。因此内核需要对其返回值做检查，并在检查不通过时进行回退。
2. 在TCP连接进入到`time-wait`状态时，原始的TCP套接口会被释放，新的tw套接口会被创建。这导致`BPF_SOCK_OPS_STATE_CB`处的程序会检查到套接口进入到close状态，并释放map中的数据，导致转发异常。而内核中又不存在一种机制来检查tw套接口的释放，因此需要新增eBPF类型实现该功能。
3. EKS使用的cgroup版本是v1，而该版本不支持eBPF，因此需要修改内核来使得cgroupv1支持eBPF。

## 三、用户手册

### 3.1 编译构建

本工具编译生成的是独立的静态二进制可执行文件，针对EKS场景，做到了轻量化。下载、编译命令为：

```shell
git clone https://git.woa.com/imagedong/eks-network
cd eks-network
make all
```

### 3.2 使用方法

```shell
$ ./eks --help
eks: eks network redirect program

Usage:
    -g, --guest      guest (pod) ip address
    -h, --host       host ip address
    -i, --nic        nic that used, such as eth0
    -v, --cgroup     cgroup version, 1 or 2
    -m, --max        max entries length
    -n, --no_prealloc no_prealloc for the tcp map
    -p, --port       port range that should be trace, such as 7777,8000-9000,9999,62550-64000
    --help           show help info
```

选项：

- `-g, --guest`：主IP（POD的IP）
- `-h, --host`：从IP（HOST的IP）
- `-i, --nic`：指定对外网口名称
- `-v, --cgroup`：cgroup版本
- `-m, --max`：最大TCP连接数（默认10W）
- `-n, --no_prealloc`：使用非预分配内存的map
- `-p, --port`：HOST使用的端口范围，可用于减少MAP中的连接数量

使用示例：

```shell
./eks -g 192.168.122.8 -h 192.168.122.100 -i eth0 -v1
```

该命令指定了主IP为`192.168.122.8`，从IP为`192.168.122.100`，对外网口为`eth0`，cgroup版本为v1。

## 四、改进优化

### 4.1 IPVS支持

**问题**

当前方案在进行连接跟踪时，是通过跟踪套接口的状态来实现的。而IPVS会对报文进行NAT，且套接口不可感知，会导致本程序连接跟踪失败，导致通过IPVS发送的报文无法回到HOST中。

**解决方法**

对IPVS进行跟踪，基于kprobe类型的eBPF来实现。其中，跟踪的函数为`ip_vs_conn_new()`，即IPVS在创建连接跟踪的时候。如果检查到IPVS跟踪的连接是HOST发出的，那么将该连接（NAT之后）的四元组也加入到控制面的ehash表中，使得响应的报文可以被重新NAT到HOST中。在对应的套接口释放时，将其对应的IPVS的四元组数据也一并释放。

### 4.2 数据优化

**问题**

由于所有的TCP连接都保存在了ehash表中，当用户的TCP连接数量很多（超过10w）的时候，会导致MAP溢出，从而NAT失败。而增加map的长度又会占用额外的内存，因此需要对这里的数据存储进行优化。

**解决办法**

控制面使用的端口范围一般都是固定的，比如`1-1024,62000-65535`，其他端口不会被使用。因此，在进行连接跟踪的时候只需要关注这些可能产生冲突的端口，其他端口直接忽略。这样，就可以大大降低ehash表中连接的数量，减少内存开销。给eks程序新增`-p, --port`参数，用于在启动时指定要监控的端口范围（不指定的话，默认监控所有端口）。