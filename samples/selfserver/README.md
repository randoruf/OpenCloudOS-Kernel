 SelfServer Project
===================

# 项目简介

SelfServer项目的目标是"免运维"，其通过在内核跟踪点运行基于EBPF的程序，可以灵活的配置策略而无需用户参与。
当前SelfServer主要包含localdns和eks-network两个项目以及公共的libbpf库。后续会持续加入”可观测“功能的项目。

# 编译准备

1. 下载elf库
```
   dnf -y install elfutils-libelf-devel
```
2. 下载bfd库
```
   dnf -y install binutils-devel
```
3. 下载cap库
```
   dnf -y install libcap-devel
```
4. 静态编译，还需要下载
```
   dnf -y install elfutils-libelf-devel-static
```

# 编译

1. 静态链接
```
   make STATIC=1
```
2. 动态链接
```
   make
```
