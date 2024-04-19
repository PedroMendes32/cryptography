#include "RSA.hpp"
#include <iostream>
constexpr auto GERAR_CHAVES = 0;
constexpr auto CRIPTOGRAFAR = 1;
constexpr auto DECRIPTOGRAFAR = 2;
constexpr auto SAIR = 3;

using namespace std;

int main(int argc, char* argv[])
{
    bool sair = false;
    while (!sair)
    {
        string nome_arquivo_original, nome_arquivo_final;
        long long int n, key;
        short int option;
        cout << "Escolha uma opção:\n";
        cout << "0. Gerar par de chaves\n";
        cout << "1. Criptografar imagem\n";
        cout << "2. Descriptografar imagem\n";
        cout << "3. Sair\n";
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
                cout << "Digite a chave publica: ";
                cin >> key;
                cout << "Digite o valor de n: ";
                cin >> n;
                RSA rsa(key, n, "PUBLIC_KEY");
                cout << "Digite o nome do arquivo original: ";
                cin >> nome_arquivo_original;
                cout << "Digite o nome do arquivo final: ";
                cin >> nome_arquivo_final;
                vector<unsigned char> image = RSA::read_image(nome_arquivo_original);
                vector<long long int> image_array_int(image.begin(), image.end());
                vector<long long int> image_encrypt_array = rsa.encrypt(image_array_int);
                rsa.write_to_file(nome_arquivo_final, image_encrypt_array);
            }
            break;
            case DECRIPTOGRAFAR:
            {
                cout << "Digite a chave privada: ";
                cin >> key;
                cout << "Digite o valor de n: ";
                cin >> n;
                RSA rsa(key, n, "PRIVATE_KEY");
                cout << "Digite o nome do arquivo original: ";
                cin >> nome_arquivo_original;
                cout << "Digite o nome do arquivo final: ";
                cin >> nome_arquivo_final;
                vector<long long int> image_encrypt = rsa.read_from_file(nome_arquivo_original);
                vector<long long int> image_decrypt_array = rsa.decrypt(image_encrypt);
                vector<unsigned char> image_decrypt(image_decrypt_array.begin(), image_decrypt_array.end());
                RSA::write_image(nome_arquivo_final, image_decrypt);
            }
            break;
            case SAIR:
            {
                sair = true;
                break;
            }
            default:
            {
                cout << "Opção inválida. Tente novamente.\n";
            }
            break;
        }
    }
    return 0;
}
