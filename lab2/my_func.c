#include<asm/segment.h>

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
		n = get_fs_byte(str + i);
		if( n >= '0' && n <= '9')
		{
			t = t*10 + n - '0';
		}
	}
	put_fs_long(t,ret);
	return(0);
}
