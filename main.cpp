#include "rsa_class/rsa.hpp"
#include "main_include/prog.hpp"
#include <iostream>
#include <cstdlib>
#include <clocale>
#include <ctime>
constexpr auto GERAR_CHAVES = 0;
constexpr auto CRIPTOGRAFAR = 1;
constexpr auto DECRIPTOGRAFAR = 2;
constexpr auto SAIR = 3;

using namespace std;

int main(int argc, char* argv[])
{
    setlocale(LC_ALL,"Portuguese");
    bool sair = false;

    while (!sair)
    {
        string nome_arquivo_original, nome_arquivo_final;
        long long int n, key;
        short int option;

        menu();
        cin >> option;

        if (cin.fail())
        {
            cout << "Erro na entrada de valores!\n";
            system("pause");
            exit(EXIT_FAILURE);
        }
        switch (option)
        {
            case GERAR_CHAVES:
            {
                gerar_chaves();
            }
            break;
            case CRIPTOGRAFAR:
            {
                criptografar(key,n,nome_arquivo_original,nome_arquivo_final); 
            }
            break;
            case DECRIPTOGRAFAR:
            {
                decriptografar(key,n,nome_arquivo_original,nome_arquivo_final); 
            }
            break;
            case SAIR:
            {
                sair = true;
                break;
            }
            default:
            {
                cout << "Opção inválida. Tente novamente.\n\n";
            }
            break;
        }
        system("pause");
        system("cls");
    }
    return 0;
}



