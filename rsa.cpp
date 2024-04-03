#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <random>

class RSA {
private:
    long long int public_key;
    long long int private_key;
    long long int n;

    bool is_prime(long long int n) const {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        for (long long int i = 5; i * i <= n; i += 6)
            if (n % i == 0 || n % (i + 2) == 0)
                return false;
        return true;
    }

    long long int generate_prime(long long int limite_inferior, long long int limite_superior, std::mt19937& rng) const {
        std::uniform_int_distribution<long long int> dist(limite_inferior, limite_superior);
        long long int prime_candidate;
        do {
            prime_candidate = dist(rng);
        } while (!is_prime(prime_candidate));
        return prime_candidate;
    }

    long long int gcd(long long int a, long long int b) const {
        if (b == 0) return a;
        return gcd(b, a % b);
    }

    long long int mod_inverse(long long int a, long long int m) const {
        long long int m0 = m, t, q;
        long long int x0 = 0, x1 = 1;
        if (m == 1) return 0;
        while (a > 1) {
            q = a / m;
            t = m;
            m = a % m, a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) x1 += m0;
        return x1;
    }

    long long int mod_pow(long long int base, long long int exponent, long long int modulus) const {
        long long int result = 1;
        base = base % modulus;
        while (exponent > 0) {
            if (exponent % 2 == 1)
                result = (result * base) % modulus;
            exponent = exponent >> 1;
            base = (base * base) % modulus;
        }
        return result;
    }

public:
    RSA() = delete;
    explicit RSA(long long int limite_inferior, long long int limite_superior) {
        if (limite_inferior >= limite_superior) {
            throw std::invalid_argument("O limite inferior deve ser menor que o limite superior.");
        }

        std::random_device rd;
        std::mt19937 rng(rd());
        long long int p = generate_prime(limite_inferior, limite_superior, rng);
        long long int q = generate_prime(limite_inferior, limite_superior, rng);
        this->n = p * q;
        long long int phi = (p - 1) * (q - 1);

        std::uniform_int_distribution<long long int> phi_dist(2, phi - 1);
        do {
            this->public_key = phi_dist(rng);
        } while (gcd(this->public_key, phi) != 1);

        this->private_key = mod_inverse(this->public_key, phi);
    }

    std::vector<long long int> encrypt(const std::vector<long long int>& data) const {
        std::vector<long long int> encrypted_data;
        encrypted_data.reserve(data.size());
        for (long long int byte : data) {
            encrypted_data.push_back(mod_pow(byte, this->public_key, this->n));
        }
        return encrypted_data;
    }

    std::vector<long long int> decrypt(const std::vector<long long int>& encrypted_data) const {
        std::vector<long long int> decrypted_data;
        decrypted_data.reserve(encrypted_data.size());
        for (long long int byte : encrypted_data) {
            decrypted_data.push_back(mod_pow(byte, this->private_key, this->n));
        }
        return decrypted_data;
    }

    void write_to_file(const std::string& filename, const std::vector<long long int>& data) const {
        std::ofstream output_file(filename, std::ios::binary);
        if (!output_file.is_open()) {
            throw std::runtime_error("Erro ao abrir o arquivo para escrita.");
        }
        for (long long int value : data) {
            output_file.write(reinterpret_cast<const char*>(&value), sizeof(value));
        }
    }

    std::vector<long long int> read_from_file(const std::string& filename) const {
        std::ifstream input_file(filename, std::ios::binary);
        if (!input_file.is_open()) {
            throw std::runtime_error("Erro ao abrir o arquivo para leitura.");
        }
        std::vector<long long int> data;
        long long int value;
        while (input_file.read(reinterpret_cast<char*>(&value), sizeof(value))) {
            data.push_back(value);
        }
        return data;
    }

    inline void print_public_key() const {
        std::cout << "Chave publica (public_key, n): " << this->public_key << ", " << n << std::endl;
    }

    inline void print_private_key() const {
        std::cout << "Chave privada (private_key, n): " << this->private_key << ", " << n << std::endl;
    }

    void writeKeysToFile(const std::string& filename) const {
        std::ofstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Erro ao abrir o arquivo para escrita.");
        }
        file << "Chave Pública: " << this->public_key << "\n";
        file << "Chave Privada: " << this->private_key << "\n";
        file << "N: " << n << "\n";
    }
};

std::vector<unsigned char> readImage(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Erro ao abrir o arquivo de imagem para leitura.");
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Erro ao ler os dados do arquivo de imagem.");
    }

    return buffer;
}

void writeImage(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Erro ao abrir o arquivo de imagem para escrita.");
    }

    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        throw std::runtime_error("Erro ao escrever os dados no arquivo de imagem.");
    }
}

int main(int argc, char *argv[]) {
    try {
        long long int limite_inferior = 100;
        long long int limite_superior = 200;

        RSA rsa(limite_inferior, limite_superior);

        std::string inputFilename = "exemplo_1.jpeg";
        std::string encryptedFilename = "exemplo_1_encrypted.bin";
        std::string decryptedFilename = "exemplo_1_decrypted.jpeg";
        std::string keyFileName = "rsa_keys.txt";
        std::vector<unsigned char> imageData = readImage(inputFilename);
       
        std::vector<long long int> plaintext(imageData.begin(), imageData.end());
        std::vector<long long int> ciphertext = rsa.encrypt(plaintext);

        rsa.write_to_file(encryptedFilename, ciphertext);

        std::vector<long long int> decryptedtext = rsa.decrypt(ciphertext);
        std::vector<unsigned char> decryptedData(decryptedtext.begin(), decryptedtext.end());

        writeImage(decryptedFilename, decryptedData);
        rsa.writeKeysToFile(keyFileName);
        std::cout << "Imagem criptografada e descriptografada com sucesso!" << std::endl;

        rsa.print_public_key();
        rsa.print_private_key();
    }
    catch (const std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
