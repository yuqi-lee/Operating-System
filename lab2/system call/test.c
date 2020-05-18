/* 有它，_syscallx等才有效。详见unistd.h */ 
#define __LIBRARY__ 

#include <unistd.h> /* 有它，编译器才能获知自定义的系统调用的编号 */ 
#include <stdio.h>
#define SIZE_OF_long 10

_syscall1(int, print_val,int, a); 
/* print_val()在用户空间的接口函数, 下同 */ 
_syscall3(int, str2num,char*,str,int,str_len, long*, ret); 




int main() 
{ 
	char s[SIZE_OF_long];
	long n;
	printf("Give me a string:\n");
	fgets(s,SIZE_OF_long,stdin);
	str2num(s,sizeof(s),&n);
	print_val(n); 
	 
	return 0; 
}
