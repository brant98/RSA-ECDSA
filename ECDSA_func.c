#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "miracl.h"
#include"ECDSA_func.h"
//前三种是采用文件输入、输出的方式进行相应操作
void ECDSA_creat_key_file(char* parameterFile, char* publicKeyFile, char* privateKeyFile)
{
	FILE* fp;
	int ep;
	epoint* g, * w;
	big a, b, p, q, x, y, d;

	miracl* mip = mirsys(1000, 16);
	time_t seed;
	time(&seed);
	irand(seed);  //随机数种子

	a = mirvar(0);
	b = mirvar(0);
	p = mirvar(0);  //192bits
	q = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	d = mirvar(0);

	fp = fopen(parameterFile, "rt"); //椭圆曲线的相关参数存放在parameter.ecs中
	if (fp == 0)
	{
		printf("Failed to open this file！\n");
		exit(1);
	}
	mip->IOBASE = 16;
	cinnum(p, fp);
	cinnum(a, fp);
	cinnum(b, fp);
	cinnum(q, fp);
	cinnum(x, fp);
	cinnum(y, fp);
	fclose(fp);
	ecurve_init(a, b, p, MR_PROJECTIVE);  //初始化椭圆曲线
	g = epoint_init();
	w = epoint_init();
	
	if (!epoint_set(x, y, 0, g)) /* initialise point of order q */
	{
		printf("1. Problem - point (x,y) is not on the curve\n");
		exit(0);
	}

	ecurve_mult(q, g, w);
	if (!point_at_infinity(w))
	{
		printf("2. Problem - point (x,y) is not of order q\n");
		exit(0);
	}

	/* generate public and private keys */
	bigrand(q, d);    //0<=d<q  
	ecurve_mult(d, g, g);

	ep = epoint_get(g, x, x);    /* compress point */


	printf("public key = %d ", ep); //输出公钥
	cotnum(x, stdout);

	fp = fopen(publicKeyFile, "wt"); //将公私钥分别存放在两个文件中 方便后续签名验证
	fprintf(fp, "%d ", ep);
	cotnum(x, fp);
	fclose(fp);

	fp = fopen(privateKeyFile, "wt");
	cotnum(d, fp);
	fclose(fp);
	printf("The public key and private key is created!\n");
}

void sign_file(char signFile[], char* privateKeyFile)  //签名消息存入 签名消息文件名.ecs文件中
{
	FILE* fp;
	char ifname[50], ofname[50];
	strcpy(ifname, signFile);
	big a, b, p, q, x, y, d, r, s, k, hash;
	epoint* g;
	miracl* mip = mirsys(1000, 16);   /* Use Hex internally */
	time_t seed;
	time(&seed);
	irand(seed);  //随机数种子
	/* get public data */
	fp = fopen("parameter.ecs", "rt");
	if (fp == NULL)
	{
		printf("file common.ecs does not exist\n");
		return 0;
	}
	a = mirvar(0);
	b = mirvar(0);
	p = mirvar(0);
	q = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	d = mirvar(0);
	r = mirvar(0);
	s = mirvar(0);
	k = mirvar(0);
	hash = mirvar(0);

	innum(p, fp);     /* modulus        */
	innum(a, fp);     /* curve parameters */
	innum(b, fp);
	innum(q, fp);     /* order of (x,y) */
	innum(x, fp);     /* (x,y) point on curve of order q */
	innum(y, fp);
	fclose(fp);

	ecurve_init(a, b, p, MR_PROJECTIVE);  /* initialise curve */
	g = epoint_init();

	if (!epoint_set(x, y, 0, g)) /* initialise point of order q */
	{
		printf("1. Problem - point (x,y) is not on the curve\n");
		exit(0);
	}

	/* calculate r - this can be done offline,
	   and hence amortized to almost nothing   */
	bigrand(q, k);

	ecurve_mult(k, g, g);
	epoint_get(g, r, r);
	divide(r, q, q);

	/* get private key of signer */
	fp = fopen(privateKeyFile, "rt");
	if (fp == NULL)
	{
		printf("file private.ecs does not exist\n");
		return 0;
	}
	innum(d, fp);
	fclose(fp);

	strcpy(ofname, ifname);
	strip(ofname);
	strcat(ofname, ".ecs");
	if ((fp = fopen(ifname, "rb")) == NULL)
	{
		printf("Unable to open file %s\n", ifname);
		return 0;
	}
	hashing(fp, hash);
	fclose(fp);
	/*计算s */
	xgcd(k, q, k, k, k);
	mad(d, r, hash, q, q, s);
	mad(s, k, k, q, q, s);
	fp = fopen(ofname, "wt");
	otnum(r, fp);
	otnum(s, fp);
	fclose(fp);
	printf("The message is signed by Alice.\n");
}

void verify_file(char signFile[], char* publicKeyFile) //签名信息在  签名消息同名的.ecs文件中 所以此处只需提供签名文件和公钥即可。
{
	FILE* fp;
	int ep;
	epoint* g, * publc;
	char ifname[50], ofname[50];
	strcpy(ifname, signFile);
	big a, b, p, q, x, y, v, u1, u2, r, s, hash;
	miracl* mip;


	fp = fopen("parameter.ecs", "rt");
	if (fp == NULL)
	{
		printf("file parameter.ecs does not exist\n");
		return 0;
	}

	mip = mirsys(1000, 16);   /* Use Hex Internally */
	a = mirvar(0);
	b = mirvar(0);
	p = mirvar(0);
	q = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);

	v = mirvar(0);
	u1 = mirvar(0);
	u2 = mirvar(0);
	s = mirvar(0);
	r = mirvar(0);
	hash = mirvar(0);

	innum(p, fp);
	innum(a, fp);
	innum(b, fp);
	innum(q, fp);
	innum(x, fp);
	innum(y, fp);

	fclose(fp);

	ecurve_init(a, b, p, MR_PROJECTIVE);  /* initialise curve */
	g = epoint_init();
	epoint_set(x, y, 0, g);
	if (!epoint_set(x, y, 0, g)) /* initialise point of order q */
	{
		printf("1. Problem - point (x,y) is not on the curve\n");
		exit(0);
	}

	/* get public key of signer */
	fp = fopen(publicKeyFile, "rt");
	if (fp == NULL)
	{
		printf("file public.ecs does not exist\n");
		return 0;
	}
	fscanf(fp, "%d", &ep);
	innum(x, fp);
	fclose(fp);

	publc = epoint_init();
	if (!epoint_set(x, x, ep, publc))  /* decompress */
	{
		printf("1. Not a point on the curve\n");
		return 0;
	}

	strcpy(ofname, ifname);
	strip(ofname);
	strcat(ofname, ".ecs");
	if ((fp = fopen(ifname, "rb")) == NULL)
	{ /* no message */
		printf("Unable to open file %s\n", ifname);
		return 0;
	}
	hashing(fp, hash);
	fclose(fp);
	fp = fopen(ofname, "rt");
	if (fp == NULL)
	{ /* no signature */
		printf("signature file %s does not exist\n", ofname);
		return 0;
	}
	innum(r, fp);
	innum(s, fp);
	fclose(fp);
	if (mr_compare(r, q) >= 0 || mr_compare(s, q) >= 0)
	{
		printf("Signature is NOT verified\n");
		return 0;
	}
	xgcd(s, q, s, s, s);
	mad(hash, s, s, q, q, u1);
	mad(r, s, s, q, q, u2);

	ecurve_mult2(u2, publc, u1, g, g);

	epoint_get(g, v, v);
	divide(v, q, q);
	if (mr_compare(v, r) == 0)
		printf("After checking.The message is form Alice\n");
	else
		printf("Signature is NOT verified.The message is not from Alice\n");
}

//不使用文件输入、输出的方式进行签名验证
void ECDSA_creat_key(paraEcdsa para, big* e, int* ep, big* d)
{
	epoint* g, * w;
	big xx;//因为x后面会改变，所以此处拷贝到xx中用。
	miracl* mip = mirsys(1000, 16);
	xx = mirvar(0);
	copy(para.x, xx);
	time_t seed;
	time(&seed);
	irand(seed);  //随机数种子
	*d = mirvar(0);

	ecurve_init(para.a, para.b, para.p, MR_PROJECTIVE);  //初始化椭圆曲线

	g = epoint_init();
	w = epoint_init();
	if (!epoint_set(xx, para.y, 0, g)) /* initialise point of order q */
	{
		printf("1. Problem - point (x,y) is not on the curve\n");
		exit(0);
	}

	ecurve_mult(para.q, g, w);
	if (!point_at_infinity(w))
	{
		printf("2. Problem - point (x,y) is not of order q\n");
		exit(0);
	}

	/* generate public and private keys */
	bigrand(para.q, *d);    //0<=d<q  
	ecurve_mult(*d, g, g);

	*ep = epoint_get(g, xx, xx);    /* compress point */

	copy(xx, *e); //*e=x
	printf("public key = %d ", *ep); //输出公钥 ep和e
	cotnum(xx, stdout);
	printf("The public key and private key is created!\n\n");
}

void sign(paraEcdsa para, char* message, big d, big* r, big* s)  //签名消息
{
	big  k, hash;
	epoint* g;
	miracl* mip = mirsys(1000, 16);   /* Use Hex internally */
	time_t seed;
	time(&seed);
	irand(seed);  //随机数种子
	k = mirvar(0);
	hash = mirvar(0);

	ecurve_init(para.a, para.b, para.p, MR_PROJECTIVE);  /* initialise curve */
	g = epoint_init();
	if (!epoint_set(para.x, para.y, 0, g)) /* initialise point of order q */
	{
		printf("1. Problem - point (x,y) is not on the curve \n");
		exit(0);
	}

	/* calculate r - this can be done offline,
	   and hence amortized to almost nothing   */
	bigrand(para.q, k);
	ecurve_mult(k, g, g);      /* see ebrick.c for method to speed this up */
	epoint_get(g, *r, *r);
	divide(*r, para.q, para.q);
	hashing(message, hash);

	/*计算s */
	xgcd(k, para.q, k, k, k);
	mad(d, *r, hash, para.q, para.q, *s);
	mad(*s, k, k, para.q, para.q, *s);
	printf("The message is signed by Alice.\n");
}

void verify(paraEcdsa para, char* message, int ep, big e,big r,big s)
{
	epoint* g, * publc;
	big v, u1, u2,hash;
	miracl* mip = mirsys(1000, 16);   /* Use Hex Internally */

	v = mirvar(0);
	u1 = mirvar(0);
	u2 = mirvar(0);
	hash = mirvar(0);

	ecurve_init(para.a, para.b, para.p, MR_PROJECTIVE);  /* initialise curve */
	g = epoint_init();
	epoint_set(para.x, para.y, 0, g);
	if (!epoint_set(para.x, para.y, 0, g)) /* initialise point of order q */
	{
		printf("1. Problem - point (x,y) is not on the curve\n");
		exit(0);
	}


	publc = epoint_init();
	if (!epoint_set(e, e, ep, publc))  /* decompress */
	{
		printf("1. Not a point on the curve\n");
		return 0;
	}

	hashing(message, hash);
	
	if (mr_compare(r, para.q) >= 0 || mr_compare(s, para.q) >= 0)
	{
		printf("Signature is NOT verified\n");
		return 0;
	}
	xgcd(s, para.q, s, s, s);
	mad(hash, s, s, para.q, para.q, u1);
	mad(r, s, s, para.q, para.q, u2);

	ecurve_mult2(u2, publc, u1, g, g);

	epoint_get(g, v, v);
	divide(v, para.q, para.q);
	if (mr_compare(v, r) == 0)
		printf("After checking.The message is form Alice\n");
	else
		printf("Signature is NOT verified.The message is not from Alice\n");

}