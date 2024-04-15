#include"rsa.hpp"
#include<Windows.h>
#include<memory>
#define CRIPTOGRAFAR    1
#define DECRIPTOGRAFAR  2
#define SAIR            3

using namespace std;

int main(int argc, char *argv[])
{
    unique_ptr<RSA> rsa_session;
    bool sair = false;
    int escolha;

    while (!sair)
    {
        menu();
        cin >> escolha;
        
        switch (escolha)
        {
            case CRIPTOGRAFAR:
            {
                criptografar(rsa_session);
            }
            break;
            case DECRIPTOGRAFAR:
            {
                decriptografar(rsa_session);
            }
            break;
            case SAIR:
            {
                sair = true;
            }
            default:
            {
                cout << "Opção inválida!\n";
            }
        }
    }

    return 0;
}

void menu (void)
{
    cout << "********************************\n"
         << "*       CRIPTOGRAFIA RSA       *\n"
         << "*                              *\n"
         << "* 1 -> Criptografar imagem.    *\n"
         << "* 2 -> Decriptografar imagem.  *\n"
         << "* 3 -> Sair do programa.       *\n"
         << "********************************\n"
         << ": ";
}

void criptografar (const unique_ptr<RSA>& rsa_session)
{
    //TODO -> Terminar a rotina
}

void decriptografar (const unique_ptr<RSA>& rsa_session)
{
    //TODO -> Terminar a rotina
}