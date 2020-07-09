#include<time.h>
#include"miracl.h"
#include"mirdef.h"
//���ļ�����RSA�㷨 ��Կ���ɡ����ܡ����ܣ���ͨ��CRT��������RSA��ǩ������ͨ��CRT��������RSA��ǩ����֤�ӿں���
void creat_key(big* p, big* q, big* n, big* d, big* e)//��˽Կ���ɺ���
{
	big p1, q1, phi, t;//p��qΪ������ɵ�������nΪ����
	time_t seed;
	time(&seed);
	irand((unsigned int)seed);//���������
	//������ʼ��
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
	//�����������
	do
	{
		bigbits(512, *p); //�ú���ʹ�õ���irand()�������512λ�Ĵ���p����Ҫע����ǲ����Ĳ�����������
		if (subdivisible(*p, 2)) //�ж������p�Ƿ�Ϊż�������Ϊż����ô��1����Ϊ������ż��һ������������
			incr(*p, 1, *p);   //p=p+1
		while (!isprime(*p))   //�ж�p�Ƿ�Ϊ��������ʱÿ�μ�2����֤pΪ��������Ϊż����
			incr(*p, 2, *p);   //�˴������Ļ�p ��Ϊһ�������ˡ�
		bigbits(512, *q);   //ͬ��ǰ������p��������ɹ��̣�������һ���������q���˴�����һһ׸����
		if (subdivisible(*q, 2))
			incr(*q, 1, *q);
		while (!isprime(*q))
			incr(*q, 2, *q);
		multiply(*p, *q, *n);      //�����ѷֽ�Ĵ��� n��nΪ���������ĳ˻��� n=p*q
		lgconv(65537L, *e);  //��long�͵�e,ת����big�͡�eΪ��Կ��һ����
		decr(*p, 1, p1);//p1=p-1,�����p��ŷ������
		decr(*q, 1, q1);//q1=q-1�������q��ŷ������
		multiply(p1, q1, phi);  //����n��ŷ��������n=p*q,��Ϊp,q��Ϊ���������Կ���������Ե�ŷ������������n��ŷ��������
	} while (xgcd(*e, phi, *d, *d, t) != 1);//e ��d����
}

big encrypt(char* text, big n, big e)//��ͨģʽ����
{

	big m, c;
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);
	c = mirvar(0);
	mip->IOBASE = 128;
	cinstr(m, text);//m=text

	mip->IOBASE = 10;
	printf("Encrypting the test string......\n");
	powmod(m, e, n, c);     //ֱ��ģ������ c=m^e mod n;
	return c;
}

void decrypt_normal(big c, big n, big d)//��ͨģʽ����
{
	big m;
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);

	//��ʼ����
	printf("\nDecrypting......\n");
	powmod(c, d, n, m);//ֱ�ӽ���ģ������ m=c^d mod n
	mip->IOBASE = 128;
	printf("\nSuccessfully the Plaintext is: ");//������ܺ������
	cotnum(m, stdout);
}

void decrypt_crt(big c, big d, big p, big q)//CRTģʽ����RSA����
{
	big  p1, q1, m, primes[2], pm[2], inv, dp, dq;//��������
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//������ʼ��
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
	decr(p, 1, p1);//p1=p-1,�����p��ŷ������
	decr(q, 1, q1);//q1=q-1�������q��ŷ������
	//CRT����
	copy(d, dp);//dp=d
	copy(d, dq);//dq=d
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 10;//�˴����׳���ת��ǰ���ܽ�������ģ���������
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
	big m, s;//m��ʾ��ǩ����Ϣ����ֵģʽ �������㣬s��ʾ��Ϣ��ǩ��
	miracl* mip = mirsys(36, 0);
	m = mirvar(0);
	s = mirvar(0);
	mip->IOBASE = 128;
	cinstr(m, text);//m=text
	mip->IOBASE = 10;
	printf("Ailce  is signing the message......\n");
	powmod(m, d, n, s);     //ֱ��ģ������ c=m^e mod n;
	return s;
}

big sign_crt(char* text, big d, big p, big q)
{
	big s, p1, q1, m, primes[2], pm[2], inv, dp, dq;//��������
	miracl* mip = mirsys(36, 0);
	big_chinese ch;
	//������ʼ��
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
	decr(p, 1, p1);//p1=p-1,�����p��ŷ������
	decr(q, 1, q1);//q1=q-1�������q��ŷ������
	//CRTǩ��
	copy(d, dp);//dp=d
	copy(d, dq);//dq=d
	divide(dp, p1, p1);   /* dp=d mod p-1 *///divide(x, y, z) z=x/y; x=x mod y
	divide(dq, q1, q1);   /* dq=d mod q-1 */

	mip->IOBASE = 128;
	cinstr(m, text);

	mip->IOBASE = 10;//�˴����׳���ת��ǰ���ܽ�������ģ���������
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
	cinstr(info, text);  //info=text��Ӧ�Ĵ���
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
