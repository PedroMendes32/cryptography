#include "RSA.hpp"
#include <iostream>
#include <cstdlib>
#include <clocale>
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
        cout << "Escolha uma opção:\n";
        cout << "0. Gerar par de chaves\n";
        cout << "1. Criptografar arquivo\n";
        cout << "2. Descriptografar arquivo\n";
        cout << "3. Sair\n";
        cout << ":";
        cin >> option;

        if (cin.fail())
        {
            cout << "Erro na entrada de valores!\n";
            exit(EXIT_FAILURE);
        }
        switch (option)
        {
            case GERAR_CHAVES:
            {
                RSA rsa(100, 9000); // TODO -> Quando o limite inferior e superior são muito grandes a criptografia apresenta problemas
                rsa.write_keys_to_file("Keys.txt");
                cout << "Par de chaves gerado!\n";
            }
            break;
            case CRIPTOGRAFAR:
            {
                cout << "\nDigite a chave pública:";
                cin >> key;
                cout << "\nDigite o valor de n:";
                cin >> n;
                RSA rsa(key, n, "PUBLIC_KEY");
                cout << "\nDigite o nome do arquivo original:";
                cin >> nome_arquivo_original;
                cout << "\nDigite o nome do arquivo final:";
                cin >> nome_arquivo_final;
                vector<unsigned char> file = RSA::read_image(nome_arquivo_original);
                vector<long long int> file_array_int(file.begin(), file.end());
                vector<long long int> file_encrypt_array = rsa.encrypt(file_array_int);
                rsa.write_to_file(nome_arquivo_final, file_encrypt_array);
            }
            break;
            case DECRIPTOGRAFAR:
            {
                cout << "\nDigite a chave privada:";
                cin >> key;
                cout << "\nDigite o valor de n:";
                cin >> n;
                RSA rsa(key, n, "PRIVATE_KEY");
                cout << "\nDigite o nome do arquivo original:";
                cin >> nome_arquivo_original;
                cout << "\nDigite o nome do arquivo final:";
                cin >> nome_arquivo_final;
                vector<long long int> file_encrypt = rsa.read_from_file(nome_arquivo_original);
                vector<long long int> file_decrypt_array = rsa.decrypt(file_encrypt);
                vector<unsigned char> file_decrypt(file_decrypt_array.begin(), file_decrypt_array.end());
                RSA::write_image(nome_arquivo_final, file_decrypt);
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
                system("pause");
            }
            break;
        }
        system("cls");
    }
    return 0;
}
