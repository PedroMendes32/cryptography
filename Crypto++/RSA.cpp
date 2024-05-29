#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <cryptlib.h>
#include <filters.h>
#include <iostream>
#include <fstream>

using namespace CryptoPP;

void GenerateRSAKeys(const std::string& privateKeyFile, const std::string& publicKeyFile)
{
    AutoSeededRandomPool rng;

    InvertibleRSAFunction params;
    params.Initialize(rng, 16384); //2048 é o padrão, se > 16384 pode dar ruim, não foi testado ainda

    RSA::PrivateKey privateKey(params);
    Base64Encoder privateKeySink(new FileSink(privateKeyFile.c_str()));
    privateKey.DEREncode(privateKeySink);
    privateKeySink.MessageEnd();

    RSA::PublicKey publicKey(params);
    Base64Encoder publicKeySink(new FileSink(publicKeyFile.c_str()));
    publicKey.DEREncode(publicKeySink);
    publicKeySink.MessageEnd();
}

void EncryptFile(const std::string& publicKeyFile, const std::string& inputFile, const std::string& encryptedFile)
{
    RSA::PublicKey publicKey;
    FileSource publicKeyFileSource(publicKeyFile.c_str(), true, new Base64Decoder);
    publicKey.BERDecode(publicKeyFileSource);

    std::ifstream ifs(inputFile);
    if (!ifs.is_open())
    {
        std::cerr << "Erro ao abrir arquivo de entrada." << std::endl;
        return;
    }
    std::string normalText((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    size_t maxText = encryptor.CiphertextLength(normalText.size());
    std::vector<byte> encryptText(maxText);
    // por algum motivo, só funciona corretamente para arquivos textos e strings diretas
    encryptor.Encrypt(rng, reinterpret_cast<const byte*>(normalText.data()), normalText.size(), &encryptText[0]);

    std::ofstream ofs(encryptedFile, std::ios::binary);
    ofs.write(reinterpret_cast<char*>(&encryptText[0]), encryptText.size());
    ofs.close();
}

void DecryptFile(const std::string& privateKeyFile, const std::string& encryptedFile, const std::string& decryptedFile)
{ 
    RSA::PrivateKey privateKey;
    FileSource privateKeyFileSource(privateKeyFile.c_str(), true, new Base64Decoder);
    privateKey.BERDecode(privateKeyFileSource);

    std::ifstream ifs(encryptedFile, std::ios::binary);
    if (!ifs.is_open())
    {
        std::cerr << "Erro ao abrir arquivo cifrado." << std::endl;
        return;
    }
    std::vector<byte> encryptText((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    size_t maxText = decryptor.MaxPlaintextLength(encryptText.size());
    std::vector<byte> decryptText(maxText);

    DecodingResult result = decryptor.Decrypt(rng, &encryptText[0], encryptText.size(), &decryptText[0]);
    if (!result.isValidCoding)
    {
        std::cerr << "Erro durante a descriptografia." << std::endl;
        return;
    }
    decryptText.resize(result.messageLength);

    std::ofstream ofs(decryptedFile);
    ofs.write(reinterpret_cast<char*>(&decryptText[0]), decryptText.size());
    ofs.close();
}

int main(void) // TESTE
{               //TODO -> Criar a rotina
    const std::string privateKeyFile = "rsa-private.key";
    const std::string publicKeyFile = "rsa-public.key";

    GenerateRSAKeys(privateKeyFile, publicKeyFile);

    const std::string inputFile = "key.txt"; 
    const std::string encryptedFile = "encrypt.dat";
    const std::string decryptedFile = "decrypt.txt"; 

    EncryptFile(publicKeyFile, inputFile, encryptedFile);

    DecryptFile(privateKeyFile, encryptedFile, decryptedFile);

    return 0;
}
