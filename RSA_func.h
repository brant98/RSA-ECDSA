#include"miracl.h"
#include"mirdef.h"

void creat_key(big* p, big* q, big* n, big* d, big* e);//密钥生成

big encrypt(char* text, big n, big e);//加密
void decrypt_normal(big c, big n, big d);//普通模式解密
void decrypt_crt(big c, big d, big p, big q);//引入CRT解密

big sign_normal(char* text, big n, big d);//普通模式签名
big sign_crt(char* text, big d, big p, big q);//引入CRT进行签名
void check_sign(char* text, big s, big e, big n);//签名验证
