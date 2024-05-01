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

        ifstream file(filename);
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
};

int main(void)
{
    return 0;
}
