#include <iostream>
#include <string>
#include <fstream>
#include <sha.h>
#include <hex.h>
#include <files.h>
#include <locale.h>

using namespace std;
using namespace CryptoPP;

namespace SHA_Algorithm
{
    string calculateFileHash(const string& filename)
    {
        SHA256 sha256;
        string hash;

        ifstream file(filename, ios::binary); // se não abrir no modo binário não funciona direito
        if (!file)
        {
            cerr << "Erro ao abrir o arquivo '" << filename << "'" << endl;
            return "";
        }

        file.seekg(0, ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, ios::beg);

        const size_t maxBufferSize = 65536;
        size_t bufferSize = min(maxBufferSize, fileSize);
        char* buffer = new char[bufferSize];

        HashFilter filter(sha256);
        filter.Attach(new HexEncoder(new StringSink(hash)));

        while (file.read(buffer, bufferSize))
        {
            filter.Put(reinterpret_cast<CryptoPP::byte*>(buffer), bufferSize);
        }
        filter.Put(reinterpret_cast<CryptoPP::byte*>(buffer), file.gcount());
        filter.MessageEnd();

        delete[] buffer;
        file.close();

        return hash;
    }
    bool compareFiles(const string& first_file_name, const string& second_file_name)
    {
        return calculateFileHash(first_file_name) == calculateFileHash(second_file_name) ? true : false;
    }
};

inline void crypto_info(void)
{
    cout << "*******************************\n";
    cout << "* SHA - Secure Hash Algorithm *\n";
    cout << "*******************************\n\n";
}

void menu(void)
{
    crypto_info();
    cout << "1 - Gerar Hash de um arquivo\n";
    cout << "2 - Verificar integridade de dados do arquivo\n";
    cout << "3 - Sair\n";
    cout << ":";
}


int main(void)
{
       setlocale(LC_ALL, "Portuguese");
   string filename;
   short int option;

    while (1)
    {
        menu();
        cin >> option;
        if (cin.fail()) exit(EXIT_FAILURE);

        switch (option)
        {
            case 1:
            {
                try
                {
                    system("cls");
                    crypto_info();
                    cout << "\n\nDigite o nome do arquivo: ";
                    cin >> filename;
                    ofstream output_file("File_Hash.txt");
                    output_file << SHA_Algorithm::calculateFileHash(filename);
                    cout << "\n\nHash do arquivo " << filename << " gerado com sucesso!\n\n";
                }
                catch (const std::exception& ex)
                {
                    cerr << "\n\nErro: " << ex.what() << "\n\n";
                }
            }
            break;
            case 2:
            {
                try
                {
                    string first, second;
                    system("cls");
                    crypto_info();
                    cout << "\n\nDigite o nome do primeiro arquivo: ";
                    cin >> first;
                    cout << "\n\nDigite o nome do segundo arquivo: ";
                    cin >> second;

                    if (SHA_Algorithm::compareFiles(first,second))
                    {
                        cout << "\n\n Os Arquivos são iguais!\n\n";
                    }
                    else
                    {
                        cout << "\n\n Os Arquivos não são iguais!\n\n";
                    }
                }
                catch (const std::exception& ex)
                {
                    cerr << "\n\nErro: " << ex.what() << "\n\n";
                }
            }
            break;
            case 3:
            {
                exit(EXIT_FAILURE);
            }
            default:
            {
                exit(EXIT_FAILURE);
            }
            system("pause");
            system("cls");
        }
    }
    return 0;
}
