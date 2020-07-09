#include <stdio.h>
#include <stdlib.h>
#include<time.h>
#include"ECDSA_func.h"
#include"RSA_func.h"
#include "miracl.h"  
#include"common_func.h"
#include"mirdef.h"
int  main()
{
	//test_rsa();  //rsa的测试
	test_fdh();  //fdh的测试
	//test_ecdsa_file();  //使用文件进行参数传递的ECDSA的测试
	//test_ecdsa();   //不适用文件，直接进行参数传递的ECDSA的测试
	return 0;
}
