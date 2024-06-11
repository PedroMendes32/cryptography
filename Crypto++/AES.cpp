#include <iostream>
#include <fstream>
#include <cstdlib>
#include <chrono>
#include <windows.h>
#include <pdh.h>
#include <psapi.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <files.h>
#include <hex.h>
#include <locale.h>
#include <iomanip> 

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

namespace AES_Algorithm
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
    /// Criptografa um arquivo usando o algoritmo AES.
    /// </summary>
    /// <param name="inputFile ->">Nome do arquivo de entrada.</param>
    /// <param name="outputFile ->">Nome do arquivo de saída criptografado.</param>
    /// <param name="key ->">Chave de criptografia.</param>
    /// <param name="is_128_bits ->">True para chave de 128 bits, False para chave de 256 bits.</param>
    void encryptAES(const string& inputFile, const string& outputFile, const string& key, bool is_128_bits)
    {
        auto start = chrono::high_resolution_clock::now();

        ifstream ifs(inputFile, ios::binary);
        ofstream ofs(outputFile, ios::binary);

        AES::Encryption aesEncryption((CryptoPP::byte*)key.data(), is_128_bits ? AES::MIN_KEYLENGTH : AES::MAX_KEYLENGTH);
        CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (CryptoPP::byte*)key.data());

        FileSource fs(ifs, true, new StreamTransformationFilter(cbcEncryption, new FileSink(ofs)));

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();


        logPerformance("Encryption", duration.count(), cpuUsage, memoryUsage);
    }

    /// <summary>
    /// Descriptografa um arquivo criptografado usando o algoritmo AES.
    /// </summary>
    /// <param name="inputFile ->">Nome do arquivo criptografado.</param>
    /// <param name="outputFile ->">Nome do arquivo de saída descriptografado.</param>
    /// <param name="key ->">Chave de descriptografia.</param>
    /// <param name="is_128_bits ->">True para chave de 128 bits, False para chave de 256 bits.</param>
    void decryptAES(const string& inputFile, const string& outputFile, const string& key, bool is_128_bits)
    {
        auto start = chrono::high_resolution_clock::now();

        ifstream ifs(inputFile, ios::binary);
        ofstream ofs(outputFile, ios::binary);

        AES::Decryption aesDecryption((CryptoPP::byte*)key.data(), is_128_bits ? AES::MIN_KEYLENGTH : AES::MAX_KEYLENGTH);
        CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte*)key.data());

        FileSource fs(ifs, true, new StreamTransformationFilter(cbcDecryption, new FileSink(ofs)));

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();


        logPerformance("Decryption", duration.count(), cpuUsage, memoryUsage);
    }

    /// <summary>
    /// Gera uma chave AES.
    /// </summary>
    /// <param name="key ->">Chave gerada.</param>
    /// <param name="is_128_bits ->">True para chave de 128 bits, False para chave de 256 bits.</param>
    void generateAESKey(string& key, bool is_128_bits)
    {
        auto start = chrono::high_resolution_clock::now();

        AutoSeededRandomPool rng;
        SecByteBlock keyData(is_128_bits ? AES::MIN_KEYLENGTH : AES::MAX_KEYLENGTH);
        rng.GenerateBlock(keyData, keyData.size());
        StringSource(keyData, keyData.size(), true, new HexEncoder(new StringSink(key)));

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();


        logPerformance("Key Generation", duration.count(), cpuUsage, memoryUsage);
    }

    /// <summary>
    /// Escreve a chave em um arquivo.
    /// </summary>
    /// <param name="key ->">Chave a ser escrita.</param>
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

int main(int argc, char* argv[])
{
    init();
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
                        AES_Algorithm::generateAESKey(key, true);
                    }
                    else if (option == 2)
                    {
                        AES_Algorithm::generateAESKey(key, false);
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
