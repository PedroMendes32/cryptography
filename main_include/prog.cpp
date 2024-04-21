#include"prog.hpp"

void menu (void)
{
    std::cout << "************************************\n";
    std::cout << "*         Criptografia RSA         *\n";
    std::cout << "************************************\n";
    std::cout << "Escolha uma opção:\n";
    std::cout << "0. Gerar par de chaves\n";
    std::cout << "1. Criptografar arquivo\n";
    std::cout << "2. Descriptografar arquivo\n";
    std::cout << "3. Sair\n";
    std::cout << ":";
}

void gerar_chaves (void) 
{
    try
    {
        RSA rsa(100, 9000); 
        rsa.write_keys_to_file("Keys.txt");
        std::cout << "Par de chaves gerado!\n\n";
    }
    catch(const std::exception& ex)
    {
        std::cerr << "Erro: " << ex.what() << std::endl;
    }
}

void criptografar (long long int& key, long long int& n, std::string& nome_arquivo_original, std::string& nome_arquivo_final)
{
    try
    {
        std::cout << "\nDigite a chave pública:";
        std::cin >> key;
        std::cout << "\nDigite o valor de n:";
        std::cin >> n;
        RSA rsa(key, n, "PUBLIC_KEY");
        std::cout << "\nDigite o nome do arquivo original:";
        std::cin >> nome_arquivo_original;
        std::cout << "\nDigite o nome do arquivo final:";
        std::cin >> nome_arquivo_final;
        std::vector<unsigned char> file = RSA::read_file(nome_arquivo_original);
        std::vector<long long int> file_array_int(file.begin(), file.end());
        std::vector<long long int> file_encrypt_array = rsa.encrypt(file_array_int);
        rsa.write_to_file(nome_arquivo_final, file_encrypt_array);
        std::cout << "Arquivo criptografado com sucesso!\n\n";
    }
    catch(const std::exception& ex)
    {
        std::cerr << "Erro: "<< ex.what() << std::endl;
    }
}

void decriptografar (long long int& key, long long int& n, std::string& nome_arquivo_original, std::string& nome_arquivo_final)
{
    try
    {
        std::cout << "\nDigite a chave privada:";
        std::cin >> key;
        std::cout << "\nDigite o valor de n:";
        std::cin >> n;
        RSA rsa(key, n, "PRIVATE_KEY");
        std::cout << "\nDigite o nome do arquivo original:";
        std::cin >> nome_arquivo_original;
        std::cout << "\nDigite o nome do arquivo final:";
        std::cin >> nome_arquivo_final;
        std::vector<long long int> file_encrypt = rsa.read_from_file(nome_arquivo_original);
        std::vector<long long int> file_decrypt_array = rsa.decrypt(file_encrypt);
        std::vector<unsigned char> file_decrypt(file_decrypt_array.begin(), file_decrypt_array.end());
        RSA::write_file(nome_arquivo_final, file_decrypt);
        std::cout << "Arquivo decriptografado com sucesso!\n\n";
    }
    catch(const std::exception& ex)
    {
        std::cerr << "Erro: " <<  ex.what() << std::endl;
    }
}




