#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "miracl.h"  
#include"mirdef.h"
#include"RSA_func.h"
//rsa相关的测试可在此文件中进行修改
void test_rsa()
{
	clock_t start, finish;
	start = clock();
	char* text = "No gains without pains!";//待加密、签名的消息
	big p, q, n, d, e, c, s;   //(n,d)私钥  (n,e)公钥  c密文  s签名
	miracl* mip = mirsys(36, 0);
	c = mirvar(0);
	s = mirvar(0);
	creat_key(&p, &q, &n, &d, &e);            //密钥生成

	c = encrypt(text, n, e);//普通模式加密   结果拷贝到密文c中
	decrypt_normal(c, n, d);           //普通模式解密

	//c = encrypt_crt(text, e, p, q);//CRT模式加密   结果拷贝到密文c中
	//decrypt_crt(c, d, p, q);           //CRT模式解密

	//s=sign_normal(text, n, d);     //普通模式对消息进行签名
	//check_sign_normal(text,s, e,n); //普通模式对签名进行验证

	//s = sign_crt(text, d, p, q);  //crt模式对消息进行签名
	//check_sign_crt(text, s,e,p, q); //crt模式进行签名验证
	//FDH
	//s = sign_crt_fdh(text, d, p, q);//RSA-FDH签名
	//check_crt_fdh(text, s, e, p, q);//RSA-FDH验证
	//printf("Test of this algorithm finished\n");
	//finish = clock();

	//printf("Start at  %f s\n", (double)start / CLOCKS_PER_SEC);
	//printf("End at %f s\n", (double)finish / CLOCKS_PER_SEC);

	//printf("1000 times tests  used %f seconds in total.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC);
	//printf("The algorithm runs once used %f seconds on average.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC / 1000);
}
