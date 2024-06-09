#include <iostream>
#include <fstream>
#include <cstdlib>
#include <chrono>
#include <windows.h>
#include <pdh.h>
#include <psapi.h>
#include <modes.h>
#include <osrng.h>
#include <locale.h>
#include <iomanip> 
#include <rsa.h>
#include <base64.h>
#include <files.h>
#include <cryptlib.h>
#include <filters.h>


#pragma comment(lib, "Pdh.lib")

using namespace CryptoPP;
using namespace std;

static PDH_HQUERY cpuQuery;
static PDH_HCOUNTER cpuTotal;

void init(void)
{
    PdhOpenQuery(NULL, NULL, &cpuQuery);
    PdhAddEnglishCounter(cpuQuery, L"\\Processor(_Total)\\% Processor Time", NULL, &cpuTotal);
    PdhCollectQueryData(cpuQuery);
}

double getCurrentValue(void)
{
    PDH_FMT_COUNTERVALUE counterVal;

    PdhCollectQueryData(cpuQuery);
    PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, NULL, &counterVal);
    return counterVal.doubleValue;
}

SIZE_T getCurrentMemoryUsageProcess(void)
{
    PROCESS_MEMORY_COUNTERS_EX pmc;
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
    SIZE_T physMemUsedByMe = pmc.WorkingSetSize;
    return physMemUsedByMe;
}

/*
* Fonte utilizada para criação dos métodos init(), getCurrentValue() e getCurrentMemoryUsage()
* https://stackoverflow.com/questions/63166/how-to-determine-cpu-and-memory-consumption-from-inside-a-process/
*/

namespace RSA_Algorithm
{
    /// <summary>
    /// Cria logs de desempenho das operações.
    /// </summary>
    /// <param name="operation ->">Descrição da operação realizada.</param>
    /// <param name="timeTaken ->">Tempo decorrido para a operação.</param>
    /// <param name="cpuUsage ->">Uso de CPU durante a operação.</param>
    /// <param name="memoryUsage ->">Uso de memória durante a operação.</param>
    void logPerformance(const string& operation, const double& timeTaken, const double& cpuUsage, const SIZE_T& memoryUsage)
    {
        ofstream logFile("performance_log.txt", ios::app);
        if (logFile.is_open())
        {
            logFile << operation << ": "
                << setprecision(6) << timeTaken << " seconds, ";
            logFile << "CPU Usage: " << setprecision(6) << cpuUsage << "%, ";
            
            logFile << "Memory Usage: " << memoryUsage << " bytes" << endl;
        }
        logFile.close();
    }

    /// <summary>
    /// Criptografa um arquivo texto usando o algoritmo RSA.
    /// </summary>
    /// <param name="publicKeyFile ->">Nome do arquivo .key da chave privada.</param>
    /// <param name="inputFile ->">Nome do arquivo que será criptografado.</param>
    /// <param name="encryptedFile ->">Nome do arquivo criptografado.</param>
    void EncryptFileRSA(const string& publicKeyFile, const string& inputFile, const string& encryptedFile)
    {
        auto start = chrono::high_resolution_clock::now();

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

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();

        logPerformance("Encryption", duration.count(), cpuUsage, memoryUsage);
    }

    /// <summary>
    /// Descriptografa um arquivo criptografado usando o algoritmo RSA.
    /// </summary>
    /// <param name="privateKeyFile ->">Nome do arquivo .key da chave privada</param>
    /// <param name="encryptedFile ->">Nome do arquivo criptografado.</param>
    /// <param name="decryptedFile ->">Nome do arquivo final descriptografado.</param>
    void DecryptFileRSA(const string& privateKeyFile, const string& encryptedFile, const string& decryptedFile)
    {
        auto start = chrono::high_resolution_clock::now();

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

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();

        logPerformance("Decryption", duration.count(), cpuUsage, memoryUsage);
    }

    /// <summary>
    /// Gera o par de chaves RSA.
    /// </summary>
    /// <param name="privateKeyFile ->">Arquivo .key da chave privada.</param>
    /// <param name="publicKeyFile ->">Arquivo .key da chave pública.</param>
    /// <param name="bits ->">Tamanho em bits da chave RSA.</param>
    void GenerateRSAKeys(const string& privateKeyFile, const string& publicKeyFile, unsigned int bits)
    {
        auto start = chrono::high_resolution_clock::now();

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

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();

        logPerformance("Key Generation", duration.count(), cpuUsage, memoryUsage);
    }
};

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
    init();
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

                RSA_Algorithm::EncryptFileRSA(publicKeyFile, fileName, "encrypt.dat");

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

                RSA_Algorithm::DecryptFileRSA(privateKeyFile, "encrypt.dat", fileName);

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
