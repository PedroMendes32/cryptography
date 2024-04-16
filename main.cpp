#include"rsa.hpp"
#include<Windows.h>
#include<memory>
#include<string>
#include<locale.h>
#define CRIPTOGRAFAR       1
#define DECRIPTOGRAFAR     2
#define SAIR               3
#define GERAR_CHAVES       4
#define USAR_CHAVE_ATUAL   5
#define USAR_CHAVE_PUBLICA 6
#define VOLTAR             7
#define USAR_CHAVE_PRIVADA 8

using namespace std;

int main(int argc, char *argv[])
{
    setlocale(LC_ALL,"Portuguese");
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

void criptografar (unique_ptr<RSA>& rsa_session)
{
    int escolha;
    string nome_arquivo_imagem,nome_arquivo_criptografado;
    vector<unsigned char> imagem_array;

    cout<< "*******************************\n"
        << "*     CRIPTOGRAFAR IMAGEM     *\n"
        << "*                             *\n"
        << "* 4 -> Gerar par de chaves.   *\n"
        << "* 5 -> Usar chaves atuais.    *\n"
        << "* 6 -> Usar chave pública.    *\n"
        << "* 7 -> Voltar.                *\n"
        << "*******************************\n"
        << ": ";

    cin >> escolha;

    switch (escolha)
    {
        case GERAR_CHAVES:
        {
            if (rsa_session != nullptr)
            {
                cout << "Já existem chaves geradas para essa sessão!\n";
                return;
            }
            try
            {
                rsa_session = make_unique<RSA>(9999999,999999999999);
                cout << "Par de chaves gerado!\n";
                rsa_session.get()->write_keys_to_file("rsa_keys.txt");
            }
            catch(const std::exception& ex)
            {
                std::cerr << ex.what() << '\n';
            }
        }
        break;

        case USAR_CHAVE_ATUAL:
        {
            if (rsa_session == nullptr)
            {
                cout << "Não existe chaves geradas para essa sessão!\n";
                return;
            }
            try
            {
                cout << "Digite o nome do arquivo de imagem completo\n";
                cout << ":";
                cin >> nome_arquivo_imagem;
                imagem_array = RSA::read_image(nome_arquivo_imagem);
                cout << "\nDigite o nome do arquivo de imagem criptografado\n";
                cout << ":";
                cin >> nome_arquivo_criptografado;
                rsa_session.get()->write_to_file(nome_arquivo_criptografado,rsa_session.get()->encrypt(vector<long long int>(imagem_array.begin(),imagem_array.end())));
                cout << "Imagem criptografada com sucesso!\n";
            }
            catch(const std::exception& ex)
            {
                std::cerr << ex.what() << '\n';
            }
        }
        break;
        case USAR_CHAVE_PUBLICA:
        {
            //TODO-> TERMINAR
        }
        break;
        case VOLTAR:
        {
            return;
        }
        default:
        {
            cout << "Opção inválida!\n";
        }
    }
}

void decriptografar (unique_ptr<RSA>& rsa_session)
{
    //TODO -> Terminar a rotina
}