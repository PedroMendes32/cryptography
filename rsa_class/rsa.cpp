#include "RSA.hpp"

bool RSA::is_prime(long long int n) const
{
    try
    {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        for (long long int i = 5; i * i <= n; i += 6)
        {
            if (n % i == 0 || n % (i + 2) == 0)
            {
                generate_log("Fim do método is_prime","Método Bem-sucedido");
                return false;
            }
        }
        generate_log("Fim do método is_prime","Método Bem-sucedido");
        return true;
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do método is_prime",std::string(ex.what()));
        std::cerr << "Erro durante verificação de número primo: " << ex.what() << std::endl;
        throw std::runtime_error("Erro durante verificação de número primo");
    }
}

long long int RSA::generate_prime(long long int limite_inferior, long long int limite_superior, std::mt19937& rng) const
{
    generate_log("Início do método generate_prime",std::nullopt);
    try
    {
        std::uniform_int_distribution<long long int> dist(limite_inferior, limite_superior);
        long long int prime_candidate;
        do
        {
            prime_candidate = dist(rng);
        }
        while (!is_prime(prime_candidate));
        generate_log("Fim do método generate_prime","Método Bem-sucedido");
        return prime_candidate;
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do método generate_prime",std::string(ex.what()));
        std::cerr << "Erro durante geração de número primo: "<< ex.what() << std::endl;
        throw std::runtime_error("Erro durante geração de número primo");
    }
}

long long int RSA::gcd(long long int a, long long int b) const //obs: como o método é recursivo, não é interessante gerar o log de início
{
    try
    {
        if (b == 0)
        {
            return a;
        }
        return gcd(b, a % b);
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do método gcd",std::string(ex.what()));
        std::cerr << "Erro durante a geração do máximo divisor comum: "<< ex.what() << std::endl;
        throw std::runtime_error("Erro durante a geração do máximo divisor comum");
    }
}

long long int RSA::mod_inverse(long long int a, long long int m) const
{
    generate_log("Início do método mod_inverse",std::nullopt);
    try
    {
        long long int m0 = m, t, q;
        long long int x0 = 0, x1 = 1;
        if (m == 1) return 0;
        while (a > 1)
        {
            q = a / m;
            t = m;
            m = a % m, a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) x1 += m0;
        generate_log("Fim do método mod_inverse","Método Bem-sucedido");
        return x1;
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do método mod_inverse",std::string(ex.what()));
        std::cerr << "Erro durante o cálculo do MOD inverso: "<< ex.what() << std::endl;
        throw std::runtime_error("Erro durante o cálculo do MOD inverso");
    }
}

long long int RSA::mod_pow(long long int base, long long int exponent, long long int modulus) const
{
    generate_log("Início do método mod_pow",std::nullopt);
    try
    {
        long long int result = 1;
        base = base % modulus;
        while (exponent > 0)
        {
            if (exponent % 2 == 1)
            {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1;
            base = (base * base) % modulus;
        }
        generate_log("Fim do método mod_pow","Método Bem-sucedido");
        return result;
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do método mod_pow",std::string(ex.what()));
        std::cerr << "Erro durante cálculo da exponenciação modular: "<< ex.what() << std::endl;
        throw std::runtime_error("Erro durante cálculo da exponenciação modular");
    }
}

RSA::RSA(long long int limite_inferior, long long int limite_superior)
{
    log = std::ofstream("Process_Log.txt");
    generate_log("Início do Construtor padrão da classe RSA",std::nullopt);
    try
    {
        if (limite_inferior >= limite_superior)
        {
            throw std::invalid_argument("O limite inferior deve ser menor que o limite superior.");
        }
        std::random_device rd;
        std::mt19937 rng(rd());
        long long int p = generate_prime(limite_inferior, limite_superior, rng);
        long long int q = generate_prime(limite_inferior, limite_superior, rng);
        this->n = p * q;
        long long int phi = (p - 1) * (q - 1);

        std::uniform_int_distribution<long long int> phi_dist(2, phi - 1);
        do
        {
            this->public_key = phi_dist(rng);
        }
        while (gcd(this->public_key, phi) != 1);

        this->private_key = mod_inverse(this->public_key, phi);
        generate_log("Fim do Construtor padrão da classe RSA","Método Bem-sucedido");
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do Construtor padrão da classe RSA",std::string(ex.what()));
        std::cerr << "Erro durante a criação do objeto: " << ex.what() << std::endl;
        throw std::runtime_error("Erro durante a criação do objeto");
    }
}

RSA::RSA(long long int private_or_public_key, long long int n, std::string type_key)
{
    log = std::ofstream("Process_Log.txt");
    generate_log("Início do Construtor com chave da classe RSA",std::nullopt);
    try
    {
        if (type_key == "PRIVATE_KEY")
        {
            this->private_key = private_or_public_key;
            this->public_key = 0;
        }
        if (type_key == "PUBLIC_KEY")
        {
            this->public_key = private_or_public_key;
            this->private_key = 0;
        }
        this->n = n;
        generate_log("Fim do Construtor com chave da classe RSA","Método Bem-sucedido");
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do Construtor com chave da classe RSA",std::string(ex.what()));
        std::cerr << "Erro durante a criação do objeto: " << ex.what() << std::endl;
        throw std::runtime_error("Erro durante a criação do objeto");
    }
}

inline long long int RSA::get_n(void) const
{
    return this->n;
}

inline long long int RSA::get_public_key(void) const
{
    return this->public_key;
}

inline long long int RSA::get_private_key(void) const
{
    return this->private_key;
}

inline void RSA::set_n(const long long int& n)
{
    this->n = n;
}

inline void RSA::set_public_key(const long long int& public_key)
{
    this->public_key = public_key;
}

inline void RSA::set_private_key(const long long int& private_key)
{
    this->private_key = private_key;
}

std::vector<long long int> RSA::encrypt(const std::vector<long long int>& data) const
{
    generate_log("Início do método encrypt",std::nullopt);
    try
    {
        std::vector<long long int> encrypted_data;
        encrypted_data.reserve(data.size());
        for (long long int byte : data)
        {
            encrypted_data.push_back(mod_pow(byte, this->public_key, this->n));
        }
        generate_log("Fim do método encrypt","Método Bem-sucedido");
        return encrypted_data;
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do método encrypt",std::string(ex.what()));
        std::cerr << "Erro durante o processo de criptografia: "<< ex.what() << std::endl;
        throw std::runtime_error("Erro durante o processo de criptografia");
    }
}

std::vector<long long int> RSA::decrypt(const std::vector<long long int>& encrypted_data) const
{
    generate_log("Início do método decrypt",std::nullopt);
    try
    {
        std::vector<long long int> decrypted_data;
        decrypted_data.reserve(encrypted_data.size());
        for (long long int byte : encrypted_data)
        {
            decrypted_data.push_back(mod_pow(byte, this->private_key, this->n));
        }
        generate_log("Fim do método decrypt","Método Bem-sucedido");
        return decrypted_data;
    }
    catch(const std::exception& ex)
    {
        generate_log("Fim do método decrypt",std::string(ex.what()));
        std::cerr << "Erro durante o processo de decriptografia: " << ex.what() << std::endl;
        throw std::runtime_error("Erro durante o processo de decriptografia");
    }
}

void RSA::write_to_file(const std::string& filename, const std::vector<long long int>& data) const
{
    std::ofstream output_file(filename, std::ios::binary);
    if (!output_file.is_open())
    {
        throw std::runtime_error("Erro ao abrir o arquivo para escrita.");
    }
    for (const long long int& value : data)
    {
        output_file.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }
}

std::vector<long long int> RSA::read_from_file(const std::string& filename) const
{
    std::ifstream input_file(filename, std::ios::binary);
    if (!input_file.is_open())
    {
        throw std::runtime_error("Erro ao abrir o arquivo para leitura.");
    }
    std::vector<long long int> data;
    long long int value;
    while (input_file.read(reinterpret_cast<char*>(&value), sizeof(value)))
    {
        data.push_back(value);
    }
    return data;
}

inline void RSA::print_public_key() const
{
    std::cout << "Chave publica (public_key, n): " << this->public_key << ", " << n << std::endl;
}

inline void RSA::print_private_key() const
{
    std::cout << "Chave privada (private_key, n): " << this->private_key << ", " << n << std::endl;
}

void RSA::write_keys_to_file(const std::string& filename) const
{
    std::ofstream file(filename);
    if (!file.is_open())
    {
        throw std::runtime_error("Erro ao abrir o arquivo para escrita.");
    }
    file << "Chave Pública: " << this->public_key << "\n";
    file << "Chave Privada: " << this->private_key << "\n";
    file << "N: " << n << "\n";
}

std::vector<unsigned char> RSA::read_file(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        throw std::runtime_error("Erro ao abrir o arquivo para leitura.");
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
    {
        throw std::runtime_error("Erro ao ler os dados do arquivo.");
    }

    return buffer;
}

void RSA::write_file(const std::string& filename, const std::vector<unsigned char>& data)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("Erro ao abrir o arquivo para escrita.");
    }

    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size()))
    {
        throw std::runtime_error("Erro ao escrever os dados no arquivo.");
    }
}

void RSA::generate_log (const std::string& method_name, const std::optional<std::string>& msg) const
{
    struct tm time = get_time();
    log << "----------------------------"; 
    log << "\n\n" << method_name << "\n";
    log << "[ Hora: " << time.tm_hour << " Minuto: " << time.tm_min << " Segundo: " << time.tm_sec << " ]";
    if (msg.has_value())
    {
        log << "\nStatus: " << msg.value();
    }
    log << "\n\n----------------------------"; 
}

struct tm RSA::get_time(void) const
{
    struct tm new_time;
    time_t now = time(0);
    localtime_s(&new_time, &now);

    return new_time;
}
