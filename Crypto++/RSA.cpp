#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <cryptlib.h>
#include <filters.h>
#include <iostream>
#include <fstream>

using namespace CryptoPP;
using namespace std;

namespace RSA_Algorithm
{
    void GenerateRSAKeys(const string& privateKeyFile, const string& publicKeyFile, unsigned int bits)
    {
        AutoSeededRandomPool rng;

        InvertibleRSAFunction params;
        params.Initialize(rng, bits);

        RSA::PrivateKey privateKey(params);
        Base64Encoder privateKeySink(new FileSink(privateKeyFile.c_str()));
        privateKey.DEREncode(privateKeySink);
        privateKeySink.MessageEnd();

        RSA::PublicKey publicKey(params);
        Base64Encoder publicKeySink(new FileSink(publicKeyFile.c_str()));
        publicKey.DEREncode(publicKeySink);
        publicKeySink.MessageEnd();
    }

    void EncryptFile(const string& publicKeyFile, const string& inputFile, const string& encryptedFile)
    {
        RSA::PublicKey publicKey;
        FileSource publicKeyFileSource(publicKeyFile.c_str(), true, new Base64Decoder);
        publicKey.BERDecode(publicKeyFileSource);

        ifstream ifs(inputFile);
        if (!ifs.is_open())
        {
            cerr << "Erro ao abrir arquivo de entrada." << endl;
            return;
        }
        string normalText((istreambuf_iterator<char>(ifs)), istreambuf_iterator<char>());
        ifs.close();

        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

        size_t maxText = encryptor.CiphertextLength(normalText.size());
        vector<byte> encryptText(maxText);
        // por algum motivo, só funciona corretamente para arquivos textos e strings diretas
        encryptor.Encrypt(rng, reinterpret_cast<const byte*>(normalText.data()), normalText.size(), &encryptText[0]);

        ofstream ofs(encryptedFile, ios::binary);
        ofs.write(reinterpret_cast<char*>(&encryptText[0]), encryptText.size());
        ofs.close();
    }

    void DecryptFile(const string& privateKeyFile, const string& encryptedFile, const string& decryptedFile)
    {
        RSA::PrivateKey privateKey;
        FileSource privateKeyFileSource(privateKeyFile.c_str(), true, new Base64Decoder);
        privateKey.BERDecode(privateKeyFileSource);

        ifstream ifs(encryptedFile, ios::binary);
        if (!ifs.is_open())
        {
            cerr << "Erro ao abrir arquivo cifrado." << endl;
            return;
        }
        vector<byte> encryptText((istreambuf_iterator<char>(ifs)), istreambuf_iterator<char>());
        ifs.close();

        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

        size_t maxText = decryptor.MaxPlaintextLength(encryptText.size());
        vector<byte> decryptText(maxText);

        DecodingResult result = decryptor.Decrypt(rng, &encryptText[0], encryptText.size(), &decryptText[0]);
        if (!result.isValidCoding)
        {
            cerr << "Erro durante a descriptografia." << endl;
            return;
        }
        decryptText.resize(result.messageLength);

        ofstream ofs(decryptedFile);
        ofs.write(reinterpret_cast<char*>(&decryptText[0]), decryptText.size());
        ofs.close();
    }
}

inline void crypto_info(void)
{
    std::cout << "*******************************\n";
    std::cout << "* RSA - Rivest-Shamir-Adleman *\n";
    std::cout << "*******************************\n\n";
}

void menu(void)
{
    crypto_info();
    std::cout << "1 - Gerar par de chaves\n";
    std::cout << "2 - Criptografar arquivo texto\n";
    std::cout << "3 - Decriptografar arquivo texto\n";
    std::cout << "4 - Sair\n";
    std::cout << ":";
}

void menu_key_size(void)
{
    crypto_info();
    std::cout << "Informe o tamanho do par de chaves RSA\n";
    std::cout << "1 -> chave de 128  bytes -> 1024  bits\n";
    std::cout << "2 -> chave de 256  bytes -> 2048  bits\n";
    std::cout << "3 -> chave de 512  bytes -> 4096  bits\n";
    std::cout << "4 -> chave de 1024 bytes -> 8192  bits\n";
    std::cout << "5 -> chave de 2048 bytes -> 16384 bits\n";
    std::cout << "6 -> chave de 4096 bytes -> 32768 bits\n";
    std::cout << ":";
}

int main(void) 
{              
    setlocale(LC_ALL, "Portuguese");
    short int option;
    const string privateKeyFile = "rsa-private.key";
    const string publicKeyFile = "rsa-public.key";
    string fileName;
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
                        unsigned int bits;
                        switch (option)
                        {
                            case 1:
                            {
                                bits = 1024;
                            }
                            break;
                            case 2:
                            {
                                bits = 2048;
                            }
                            break;
                            case 3:
                            {
                                bits = 4096;
                            }
                            break;
                            case 4:
                            {
                                bits = 8192;
                            }
                            break;
                            case 5:
                            {
                                bits = 16384;
                            }
                            break;
                            case 6:
                            {
                                bits = 32768;
                            }
                            break;
                        }

                        RSA_Algorithm::GenerateRSAKeys(privateKeyFile, publicKeyFile, bits);
                        std::cout << "\n\n Par de chaves gerado com sucesso!\n\n";
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
                    std::cout << "Digite o nome do arquivo texto que sera criptografado: ";
                    cin >> fileName;

                    RSA_Algorithm::EncryptFile(publicKeyFile, fileName, "encrypt.dat");
                   
                    std::cout << "\n\nArquivo criptografado com sucesso!\n\n";
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
                    std::cout << "Digite o nome do arquivo final: ";
                    cin >> fileName;

                    RSA_Algorithm::DecryptFile(privateKeyFile, "encrypt.dat", fileName);

                    std::cout << "\n\nArquivo decriptografado com sucesso!\n\n";
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
