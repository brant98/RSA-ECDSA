#include <stdio.h>
#include "miracl.h"
#include <stdlib.h>

void strip(char* name)//��ȡ�ļ���
{
    int i;
    for (i = 0; name[i] != '\0'; i++)
    {
        if (name[i] != '.') continue;
        name[i] = '\0';
        break;
    }
}

void hashing(char* message, big hash)//������Ϣ�Ĺ�ϣժҪ
{ 
    char h[20];
    int ch;
    sha sh;
    shs_init(&sh);
    for (int i = 0; i < strlen(message); i++)
    {
        ch = message[i];
        shs_process(&sh, ch);
    }
    shs_hash(&sh, h);
    bytes_to_big(20, h, hash);
}