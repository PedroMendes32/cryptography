#include<iostream>
#include<fstream>
#include<cstdlib>
#include<aes.h>
#include<modes.h>
#include<osrng.h>
#include<files.h>
#include<hex.h>
#include<locale.h>

using namespace CryptoPP;
using namespace std;

namespace AES_Algorithm
{
    void encryptAES(const string& inputFile, const string& outputFile, const string& key, bool is_128_bits)
    {
        ifstream ifs(inputFile, ios::binary);
        ofstream ofs(outputFile, ios::binary);

        AES::Encryption aesEncryption((CryptoPP::byte*)key.data(), is_128_bits == true ? AES::MIN_KEYLENGTH : AES::MAX_KEYLENGTH);
        CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (CryptoPP::byte*)key.data());

        FileSource fs(ifs, true, new StreamTransformationFilter(cbcEncryption, new FileSink(ofs)));
    }

    void decryptAES(const string& inputFile, const string& outputFile, const string& key, bool is_128_bits)
    {
        ifstream ifs(inputFile, ios::binary);
        ofstream ofs(outputFile, ios::binary);

        AES::Decryption aesDecryption((CryptoPP::byte*)key.data(), is_128_bits == true ? AES::MIN_KEYLENGTH : AES::MAX_KEYLENGTH);
        CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte*)key.data());

        FileSource fs(ifs, true, new StreamTransformationFilter(cbcDecryption, new FileSink(ofs)));
    }

    void generateAESKey(string& key, bool is_128_bits)
    {
        AutoSeededRandomPool rng;
        SecByteBlock keyData(is_128_bits == true ? AES::MIN_KEYLENGTH : AES::MAX_KEYLENGTH);
        rng.GenerateBlock(keyData, keyData.size());
        StringSource(keyData, keyData.size(), true, new HexEncoder(new StringSink(key)));
    }

    void writeKeyToFile(const string& key)
    {
        ofstream keyFile("AES_Key.txt");
        if (keyFile.is_open())
        {
            keyFile << key;
        }
        keyFile.close();
    }
};

inline void crypto_info(void)
{
    cout << "**************************************\n";
    cout << "* AES - Advanced Encryption Standard *\n";
    cout << "**************************************\n\n";
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

void menu_key_size(void)
{
    crypto_info();
    cout << "Informe o tamanho da chave\n";
    cout << "1 -> chave de 16 bytes -> 128 bits\n";
    cout << "2 -> chave de 32 bytes -> 256 bits\n";
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
                    menu_key_size();
                    cin >> option;
                    if (!cin.fail())
                    {
                        if (option == 1)
                        {
                            AES_Algorithm::generateAESKey(key,true);
                        }
                        else if (option == 2)
                        {
                            AES_Algorithm::generateAESKey(key,false);
                        }
                        else
                        {
                            exit(EXIT_FAILURE);
                        }
                        AES_Algorithm::writeKeyToFile(key);
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
                    menu_key_size();
                    cin >> option;
                    if (cin.fail()) exit(EXIT_FAILURE);

                    if (option == 1)
                    {
                        cout << "\n\nInforme o nome do arquivo que será criptografado: ";
                        cin >> file_name;
                        cout << "\n\nInforme o valor do chave: ";
                        cin >> key;
                        AES_Algorithm::encryptAES(file_name, "encrypt_file.dat", key, true);
                    }
                    else if (option == 2)
                    {
                        cout << "\n\nInforme o nome do arquivo que será criptografado: ";
                        cin >> file_name;
                        cout << "\n\nInforme o valor do chave: ";
                        cin >> key;
                        AES_Algorithm::encryptAES(file_name, "encrypt_file.dat", key, false);
                    }
                    else
                    {
                        exit(EXIT_FAILURE);
                    }
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
                    menu_key_size();
                    cin >> option;
                    if (cin.fail()) exit(EXIT_FAILURE);

                    if (option == 1)
                    {
                        cout << "\n\nInforme o nome do arquivo com a extensão original: ";
                        cin >> file_name;
                        cout << "\n\nInforme o valor do chave: ";
                        cin >> key;
                        AES_Algorithm::decryptAES("encrypt_file.dat", file_name, key, true);
                    }
                    else if (option == 2)
                    {
                        cout << "\n\nInforme o nome do arquivo com a extensão original: ";
                        cin >> file_name;
                        cout << "\n\nInforme o valor do chave: ";
                        cin >> key;
                        AES_Algorithm::decryptAES("encrypt_file.dat", file_name, key, false);
                    }
                    else
                    {
                        exit(EXIT_FAILURE);
                    }
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