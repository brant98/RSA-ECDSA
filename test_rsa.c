#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "miracl.h"  
#include"mirdef.h"
#include"RSA_func.h"
//rsa��صĲ��Կ��ڴ��ļ��н����޸�
void test_rsa()
{
	clock_t start, finish;
	start = clock();
	char* text = "No gains without pains!";//�����ܡ�ǩ������Ϣ
	big p, q, n, d, e, c, s;   //(n,d)˽Կ  (n,e)��Կ  c����  sǩ��
	miracl* mip = mirsys(36, 0);
	c = mirvar(0);
	s = mirvar(0);
	creat_key(&p, &q, &n, &d, &e);            //��Կ����

	c = encrypt(text, n, e);//��ͨģʽ����   �������������c��
	decrypt_normal(c, n, d);           //��ͨģʽ����

	//c = encrypt_crt(text, e, p, q);//CRTģʽ����   �������������c��
	//decrypt_crt(c, d, p, q);           //CRTģʽ����

	//s=sign_normal(text, n, d);     //��ͨģʽ����Ϣ����ǩ��
	//check_sign_normal(text,s, e,n); //��ͨģʽ��ǩ��������֤

	//s = sign_crt(text, d, p, q);  //crtģʽ����Ϣ����ǩ��
	//check_sign_crt(text, s,e,p, q); //crtģʽ����ǩ����֤
	//FDH
	//s = sign_crt_fdh(text, d, p, q);//RSA-FDHǩ��
	//check_crt_fdh(text, s, e, p, q);//RSA-FDH��֤
	//printf("Test of this algorithm finished\n");
	//finish = clock();

	//printf("Start at  %f s\n", (double)start / CLOCKS_PER_SEC);
	//printf("End at %f s\n", (double)finish / CLOCKS_PER_SEC);

	//printf("1000 times tests  used %f seconds in total.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC);
	//printf("The algorithm runs once used %f seconds on average.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC / 1000);
}
