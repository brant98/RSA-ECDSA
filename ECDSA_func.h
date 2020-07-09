#include "miracl.h"
typedef struct paraEcdsa
{
	big p, a, b, q, x, y;
}paraEcdsa;
void ECDSA_creat_key_file(char* parameterFile, char* publicKeyFile, char* privateKeyFile);
void sign_file(char signFile[], char* privateKeyFile);
void verify_file(char signFile[], char* publicKeyFile);

void ECDSA_creat_key(paraEcdsa para, big* e, int* ep, big* d);
void sign(paraEcdsa para, char* message, big d, big* r, big* s);
void verify(paraEcdsa para, char* message, int ep, big e, big r, big s);