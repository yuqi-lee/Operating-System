#include<asm/segment.h>

/*新增的两个系统调用代码*/

int sys_print_val(int a)
{
	printk("in sys_print_val: %d\n",a);
	return(0);
}

int sys_str2num(char *str, int str_len, long *ret)
{
	int i;
	int n;
	long t;
	t = 0; 
	for(i = 0; i < str_len ; i++)
	{	
		n = get_fs_byte(str + i);	/*从用户态传递数据至内核*/
		if( n >= '0' && n <= '9')
		{
			t = t*10 + n - '0';
		}
	}
	put_fs_long(t,ret);	/*数据传递回用户态*/
	return(0);
}
