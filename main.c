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
	//test_rsa();  //rsa�Ĳ���
	test_fdh();  //fdh�Ĳ���
	//test_ecdsa_file();  //ʹ���ļ����в������ݵ�ECDSA�Ĳ���
	//test_ecdsa();   //�������ļ���ֱ�ӽ��в������ݵ�ECDSA�Ĳ���
	return 0;
}
