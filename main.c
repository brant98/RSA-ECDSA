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
	//test_ecdsa_file();  //使用文件进行参数传递的ECDSA的测试
	//test_ecdsa();   //不适用文件，直接进行参数传递的ECDSA的测试



	int ep;
	big a, b, e, p, q, x, y, d, r, s;
	miracl* mip = mirsys(1000, 256);
	time_t seed;
	time(&seed);
	irand(seed);  //随机数种子
	paraEcdsa para;
	char* message = "Be there or be square!";

	para.a = mirvar(0);
	para.b = mirvar(0);
	para.p = mirvar(0);  //192bits
	para.q = mirvar(0);
	para.x = mirvar(0);
	para.y = mirvar(0);
	d = mirvar(0);
	e = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);

	mip->IOBASE = 16;
	cinstr(para.p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
	cinstr(para.a, "-3");
	cinstr(para.b, "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
	cinstr(para.q, "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
	cinstr(para.x, "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012");
	cinstr(para.y, "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");




	printf("Test of ecdsa.\n");
	clock_t start, finish;
	start = clock();

	for (int i = 0; i < 1000; i++) {
	ECDSA_creat_key(para, &e, &ep, &d);
	sign(para, message, d, &r, &s);
		verify(para, message, ep, e, r, s);
	}
	printf("Test of this algorithm finished\n");
	finish = clock();

	printf("Start at  %f s\n", (double)start / CLOCKS_PER_SEC);
	printf("End at %f s\n", (double)finish / CLOCKS_PER_SEC);

	printf("1000 times tests  used %f seconds in total.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC);
	printf("The algorithm runs once used %f seconds on average.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC / 1000);


	return 0;
}
