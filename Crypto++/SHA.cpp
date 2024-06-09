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
#include <sha.h>
#include <hex.h>
#include <files.h>


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

namespace SHA_Algorithm
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
    /// Calcula o valor Hash do conteúdo de um arquivo
    /// </summary>
    /// <param name="filename ->">Nome do arquivo para gerar o Hash.</param>
    string calculateFileHash(const string& filename)
    {
        auto start = chrono::high_resolution_clock::now();

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

        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        double cpuUsage = getCurrentValue();
        SIZE_T memoryUsage = getCurrentMemoryUsageProcess();

        logPerformance("Hash Generation", duration.count(), cpuUsage, memoryUsage);
        return hash;
    }

    /// <summary>
    /// Compara o valor hash do conteúdo de dois arquivos
    /// </summary>
    /// <param name="first_file_name ->">Nome do primeiro arquivo.</param>
    /// <param name="second_file_name ->">Nome do segundo arquivo.</param>
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
    cout << "2 - Comparar conteudo de arquivos \n";
    cout << "3 - Sair\n";
    cout << ":";
}

int main(void)
{
    init();
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

                if (SHA_Algorithm::compareFiles(first, second))
                {
                    cout << "\n\n Os Arquivos sao iguais!\n\n";
                }
                else
                {
                    cout << "\n\n Os Arquivos nao sao iguais!\n\n";
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
        }
        system("pause");
        system("cls");
    }
    return 0;
}
