#include<iostream>
#include<fstream>
#include<cstdlib>
#include<des.h>
#include<modes.h>
#include<osrng.h>
#include<files.h>
#include<hex.h>
#include<locale.h>

using namespace CryptoPP;
using namespace std;

namespace DES_Algorithm
{
    void encryptDES(const std::string& inputFile, const std::string& outputFile, const std::string& key)
    {
        std::ifstream ifs(inputFile, std::ios::binary);
        std::ofstream ofs(outputFile, std::ios::binary);

        DES::Encryption desEncryption((CryptoPP::byte*)key.data(), DES::MAX_KEYLENGTH);
        CBC_Mode_ExternalCipher::Encryption cbcEncryption(desEncryption, (CryptoPP::byte*)key.data());

        FileSource fs(ifs, true, new StreamTransformationFilter(cbcEncryption, new FileSink(ofs)));
    }
    void decryptDES(const std::string& inputFile, const std::string& outputFile, const std::string& key)
    {
        std::ifstream ifs(inputFile, std::ios::binary);
        std::ofstream ofs(outputFile, std::ios::binary);

        DES::Decryption desDecryption((CryptoPP::byte*)key.data(), DES::MAX_KEYLENGTH);
        CBC_Mode_ExternalCipher::Decryption cbcDecryption(desDecryption, (CryptoPP::byte*)key.data());

        FileSource fs(ifs, true, new StreamTransformationFilter(cbcDecryption, new FileSink(ofs)));
    }
    void generateDESKey(std::string& key)
    {
        AutoSeededRandomPool rng;
        SecByteBlock keyData(DES::MAX_KEYLENGTH);
        rng.GenerateBlock(keyData, keyData.size());
        StringSource(keyData, keyData.size(), true, new HexEncoder(new StringSink(key)));
    }
    void writeKeyToFile(const std::string& key)
    {
        std::ofstream keyFile("DES_Key.txt");
        if (keyFile.is_open())
        {
            keyFile << key;
        }
        keyFile.close();
    }
};

inline void crypto_info(void)
{
    cout << "**********************************\n";
    cout << "* DES - Data Encryption Standard *\n";
    cout << "**********************************\n\n";
}

void menu(void)
{
    crypto_info();
    cout << "1 - Gerar chave\n";
    cout << "2 - Criptografar arquivo\n";
    cout << "3 - Decriptografar arquivo\n";
    cout << "4 - Sair\n";
    cout << ":";
}


int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "Portuguese");
    short int option;
    string file_name;
    string key;

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
                    if (!cin.fail())
                    {
                        DES_Algorithm::generateDESKey(key);
                        DES_Algorithm::writeKeyToFile(key);
                        cout << "\n\nChave gerada com sucesso!\n\n";
                    }
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
                    system("cls");
                    crypto_info();
                    if (cin.fail()) exit(EXIT_FAILURE);

                    cout << "\n\nInforme o nome do arquivo que será criptografado: ";
                    cin >> file_name;
                    cout << "\n\nInforme o valor do chave: ";
                    cin >> key;
                    DES_Algorithm::encryptDES(file_name, "encrypt_file.dat", key);
                  
                    cout << "\n\nArquivo criptografado com sucesso!\n\n";
                }
                catch (const std::exception& ex)
                {
                    cerr << "\n\nErro: " << ex.what() << "\n\n";
                }
            }
            break;
            case 3:
            {
                try
                {
                    system("cls");
                    crypto_info();
                    if (cin.fail()) exit(EXIT_FAILURE);
                    
                    cout << "\n\nInforme o nome do arquivo com a extensão original: ";
                    cin >> file_name;
                    cout << "\n\nInforme o valor do chave: ";
                    cin >> key;
                    DES_Algorithm::decryptDES("encrypt_file.dat", file_name, key);
                   
                    cout << "\n\nArquivo decriptografado com sucesso!\n\n";
                }
                catch (const std::exception& ex)
                {
                    cerr << "\n\nErro: " << ex.what() << "\n\n";
                }
            }
            break;
            case 4:
            {
                exit(EXIT_FAILURE);
            }
            default:
                exit(EXIT_FAILURE);
        }
        system("pause");
        system("cls");
    }
    return 0;
}