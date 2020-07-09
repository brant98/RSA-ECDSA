#include"miracl.h"
#include"mirdef.h"

void creat_key(big* p, big* q, big* n, big* d, big* e);//密钥生成
//RSA加密解密
big encrypt(char* text, big n, big e);//加密
void decrypt_normal(big c, big n, big d);//普通模式解密
void decrypt_crt(big c, big d, big p, big q);//引入CRT解密
//RSA签名
big sign_normal(char* text, big n, big d);//普通模式签名
big sign_crt(char* text, big d, big p, big q);//引入CRT进行签名
void check_sign(char* text, big s, big e, big n);//签名验证

//RSA-FDH算法
big sign_crt_fdh(char* text, big d, big p, big q); //crt模式RSA-FDH
void check_fdh(char* text, big s, big e, big n);   //fdh签名验证
