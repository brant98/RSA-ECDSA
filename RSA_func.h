#include"miracl.h"
#include"mirdef.h"

void creat_key(big* p, big* q, big* n, big* d, big* e);//��Կ����
//RSA���ܽ���
big encrypt(char* text, big n, big e);//����
void decrypt_normal(big c, big n, big d);//��ͨģʽ����
void decrypt_crt(big c, big d, big p, big q);//����CRT����
//RSAǩ��
big sign_normal(char* text, big n, big d);//��ͨģʽǩ��
big sign_crt(char* text, big d, big p, big q);//����CRT����ǩ��
void check_sign(char* text, big s, big e, big n);//ǩ����֤

//RSA-FDH�㷨
big sign_crt_fdh(char* text, big d, big p, big q); //crtģʽRSA-FDH
void check_fdh(char* text, big s, big e, big n);   //fdhǩ����֤
