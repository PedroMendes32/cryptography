#include <iostream>
#include <fstream>
#include <cstdlib>
#include <chrono>
#include <windows.h>
#include <pdh.h>
#include <psapi.h>
#include <des.h>
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

namespace DES_Algorithm
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
    /// Criptografa um arquivo usando o algoritmo DES.
    /// </summary>
    /// <param name="inputFile ->">Nome do arquivo de entrada.</param>
    /// <param name="outputFile ->">Nome do arquivo de saída criptografado.</param>
    /// <param name="key ->">Chave de criptografia.</param>
    void encryptDES(const std::string& inputFile, const std::string& outputFile, const std::string& key)
    {
        auto start = chrono::high_resolution_clock::now();

        ifstream ifs(inputFile, ios::binary);
        ofstream ofs(outputFile, ios::binary);

        DES::Encryption desEncryption((CryptoPP::byte*)key.data(), DES::MAX_KEYLENGTH);
        CBC_Mode_ExternalCipher::Encryption cbcEncryption(desEncryption, (CryptoPP::byte*)key.data());

        FileSource fs(ifs, true, new StreamTransformationFilter(cbcEncryption, new FileSink(ofs)));

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();

        logPerformance("Encryption", duration.count(), cpuUsage, memoryUsage);
    }

    /// <summary>
    /// Descriptografa um arquivo criptografado usando o algoritmo DES.
    /// </summary>
    /// <param name="inputFile ->">Nome do arquivo criptografado.</param>
    /// <param name="outputFile ->">Nome do arquivo de saída descriptografado.</param>
    /// <param name="key ->">Chave de descriptografia.</param>
    void decryptDES(const std::string& inputFile, const std::string& outputFile, const std::string& key)
    {
        auto start = chrono::high_resolution_clock::now();

        std::ifstream ifs(inputFile, std::ios::binary);
        std::ofstream ofs(outputFile, std::ios::binary);

        DES::Decryption desDecryption((CryptoPP::byte*)key.data(), DES::MAX_KEYLENGTH);
        CBC_Mode_ExternalCipher::Decryption cbcDecryption(desDecryption, (CryptoPP::byte*)key.data());

        FileSource fs(ifs, true, new StreamTransformationFilter(cbcDecryption, new FileSink(ofs)));

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();

        logPerformance("Decryption", duration.count(), cpuUsage, memoryUsage);
    }

    /// <summary>
    /// Gera uma chave DES.
    /// </summary>
    /// <param name="key ->">Chave gerada.</param>
    void generateDESKey(std::string& key)
    {
        auto start = chrono::high_resolution_clock::now();

        AutoSeededRandomPool rng;
        SecByteBlock keyData(DES::MAX_KEYLENGTH);
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
                crypto_info();
                if (!cin.fail())
                {
                    DES_Algorithm::generateDESKey(key);
                    DES_Algorithm::writeKeyToFile(key);
                    cout << "\n\nChave gerada com sucesso!\n\n";
                }
            }
            catch (const exception& ex)
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

                cout << "\n\nInforme o nome do arquivo que sera criptografado: ";
                cin >> file_name;
                cout << "\n\nInforme o valor do chave: ";
                cin >> key;
                DES_Algorithm::encryptDES(file_name, "encrypt_file.dat", key);

                cout << "\n\nArquivo criptografado com sucesso!\n\n";
            }
            catch (const exception& ex)
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

                cout << "\n\nInforme o nome do arquivo com a extensao original: ";
                cin >> file_name;
                cout << "\n\nInforme o valor do chave: ";
                cin >> key;
                DES_Algorithm::decryptDES("encrypt_file.dat", file_name, key);

                cout << "\n\nArquivo decriptografado com sucesso!\n\n";
            }
            catch (const exception& ex)
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