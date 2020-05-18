# 文件说明

## “/system call”目录下
* my_func.c： 新增两个系统调用的源代码
* test.c:	测试新增的系统调用
* 其余文件：增加系统调用时修改的/linux/kernel 以及/linux/include 目录下的文件
* 原工程的 Makefile 也需要进行相应修改

## shell.c
一个自编的简单 shell 程序，支持子命令，支持通过管道通信来完成带有管道符号(*)的命令实现
