#include<time.h>
#include"miracl.h"
#include"mirdef.h"
//此文件，是RSA算法 密钥生成、加密、解密（普通、CRT）、基于RSA的签名（普通、CRT）、基于RSA的签名验证接口函数
void creat_key(big* p, big* q, big* n, big* d, big* e)//公私钥生成函数
{
	big p1, q1, phi, t;//p和q为随机生成的素数，n为大数
	time_t seed;
	time(&seed);
	irand((unsigned int)seed);//随机数种子
	//变量初始化
	*p = mirvar(0);
	*q = mirvar(0);
	*n = mirvar(0);
	*d = mirvar(0);
	*e = mirvar(0);
	p1 = mirvar(0);
	q1 = mirvar(0);
	phi = mirvar(0);
	t = mirvar(0);
	//printf("Now generating 512-bit random primes p and q\n\n");
	//生成随机素数
	do
	{
		bigbits(512, *p); //该函数使用到了irand()随机产生512位的大数p，需要注意的是产生的并非是素数。
		if (subdivisible(*p, 2)) //判断随机数p是否为偶数，如果为偶数那么加1，即为奇数，偶数一定不是素数。
			incr(*p, 1, *p);   //p=p+1
		while (!isprime(*p))   //判断p是否为素数，此时每次加2，保证p为奇数，不为偶数。
			incr(*p, 2, *p);   //此处结束的话p 便为一个素数了。
		bigbits(512, *q);   //同理前面素数p的随机生成过程，生成另一个随机素数q。此处不再一一赘述。
		if (subdivisible(*q, 2))
			incr(*q, 1, *q);
		while (!isprime(*q))
			incr(*q, 2, *q);
		multiply(*p, *q, *n);      //生成难分解的大数 n，n为两个素数的乘积， n=p*q
		lgconv(65537L, *e);  //将long型的e,转换成big型。e为公钥的一部分
		decr(*p, 1, p1);//p1=p-1,计算出p的欧拉函数
		decr(*q, 1, q1);//q1=q-1，计算出q的欧拉函数
		multiply(p1, q1, phi);  //计算n的欧拉函数，n=p*q,因为p,q都为素数，所以可以用其各自的欧拉函数来计算n的欧拉函数。
	} while (xgcd(*e, phi, *d, *d, t) != 1);//e 和d互素
}

big encrypt(char* text, big n, big e)//普通模式加密
{

	big m, c;
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);
	c = mirvar(0);
	mip->IOBASE = 128;
	cinstr(m, text);//m=text

	mip->IOBASE = 10;
	printf("Encrypting the test string......\n");
	powmod(m, e, n, c);     //直接模幂运算 c=m^e mod n;
	return c;
}

void decrypt_normal(big c, big n, big d)//普通模式解密
{
	big m;
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);

	//开始解密
	printf("\nDecrypting......\n");
	powmod(c, d, n, m);//直接进行模幂运算 m=c^d mod n
	mip->IOBASE = 128;
	printf("\nSuccessfully the Plaintext is: ");//输出解密后的明文
	cotnum(m, stdout);
}

void decrypt_crt(big c, big d, big p, big q)//CRT模式进行RSA解密
{
	big  p1, q1, m, primes[2], pm[2], inv, dp, dq;//变量定义
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//变量初始化
	p1 = mirvar(0);
	q1 = mirvar(0);
	m = mirvar(0);
	primes[0] = mirvar(0);
	primes[1] = mirvar(0);
	pm[0] = mirvar(0);
	pm[1] = mirvar(0);
	inv = mirvar(0);
	dp = mirvar(0);
	dq = mirvar(0);

	primes[0] = p;
	primes[1] = q;
	crt_init(&ch, 2, primes);
	xgcd(p, q, inv, inv, inv);   /* 1/p mod q */
	decr(p, 1, p1);//p1=p-1,计算出p的欧拉函数
	decr(q, 1, q1);//q1=q-1，计算出q的欧拉函数
	//CRT解密
	copy(d, dp);//dp=d
	copy(d, dq);//dq=d
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 10;//此处容易出错，转换前不能进行运算的，否则会出错。
	printf("\nDecrypting test string\n");
	powmod(c, dp, p, pm[0]);    /* get result mod p */
	powmod(c, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, m);
	mip->IOBASE = 128;
	printf("Successfully the Plaintext is: ");
	cotnum(m, stdout);
	crt_end(&ch);
}

big sign_normal(char* text, big n, big d)
{
	big m, s;//m表示待签名消息的数值模式 方便运算，s表示消息的签名
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);
	s = mirvar(0);
	mip->IOBASE = 128;
	cinstr(m, text);//m=text
	mip->IOBASE = 10;
	printf("Ailce  is signing the message......\n");
	powmod(m, d, n, s);     //直接模幂运算 c=m^e mod n;
	return s;
}

big sign_crt(char* text, big d, big p, big q)
{
	big s, p1, q1, m, primes[2], pm[2], inv, dp, dq;//变量定义
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//变量初始化
	s = mirvar(0);
	p1 = mirvar(0);
	q1 = mirvar(0);
	m = mirvar(0);
	primes[0] = mirvar(0);
	primes[1] = mirvar(0);
	pm[0] = mirvar(0);
	pm[1] = mirvar(0);
	inv = mirvar(0);
	dp = mirvar(0);
	dq = mirvar(0);

	primes[0] = p;
	primes[1] = q;
	crt_init(&ch, 2, primes);
	xgcd(p, q, inv, inv, inv);   /* 1/p mod q */
	decr(p, 1, p1);//p1=p-1,计算出p的欧拉函数
	decr(q, 1, q1);//q1=q-1，计算出q的欧拉函数
	//CRT签名
	copy(d, dp);//dp=d
	copy(d, dq);//dq=d
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 128;
	cinstr(m, text);

	mip->IOBASE = 10;//此处容易出错，转换前不能进行运算的，否则会出错。
	printf("\nAlice is signing the message!\n");
	powmod(m, dp, p, pm[0]);    /* get result mod p */
	powmod(m, dq, q, pm[1]);    /* get result mod q */
	crt(&ch, pm, s);
	return s;
}

void check_sign(char* text, big s, big e, big n)
{
	big info, temp;
	miracl* mip = mirsys(36, 0);
	info = mirvar(0);
	temp = mirvar(0);
	mip->IOBASE = 128;
	cinstr(info, text);  //info=text对应的大数
	mip->IOBASE = 10;
	powmod(s, e, n, temp);
	if (mr_compare(temp, info) == 0)
	{
		printf("After checking the signature,the result shows that this message is signed by Alice!\n");
	}
	else {
		printf("The result shows that this is not signed by Alice!");
	}

}
