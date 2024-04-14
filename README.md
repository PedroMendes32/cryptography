# RSA - Implementação do Algoritmo de Criptografia RSA

A classe `RSA` implementa o algoritmo de criptografia RSA (Rivest-Shamir-Adleman) para criptografia e decriptografia de imagens sem a utilização de bibliotecas prontas. O RSA é um dos algoritmos de criptografia assimétrica mais amplamente utilizados para comunicações seguras na internet, como criptografia de dados, assinaturas digitais e troca de chaves.

## Principais Funções

### Construtor
```cpp
explicit RSA(long long int limite_inferior, long long int limite_superior);
```
Cria uma instância da classe RSA com chaves pública e privada geradas dentro do intervalo especificado pelos parâmetros `limite_inferior` e `limite_superior`. As chaves são calculadas internamente durante a inicialização do objeto.

### Métodos de Acesso
```cpp
inline long long int get_n(void) const;
inline long long int get_public_key(void) const;
inline long long int get_private_key(void) const;
inline void set_n(const long long int& n);
inline void set_public_key(const long long int& public_key);
inline void set_private_key(const long long int& private_key);
```
Esses métodos permitem acessar e modificar os atributos `n`, `public_key` e `private_key` da instância RSA.

### Criptografia e Descriptografia
```cpp
std::vector<long long int> encrypt(const std::vector<long long int>& data) const;
std::vector<long long int> decrypt(const std::vector<long long int>& encrypted_data) const;
```
Esses métodos permitem criptografar e descriptografar imagens usando as chaves pública e privada, respectivamente.

### Operações de Arquivo
```cpp
void write_to_file(const std::string& filename, const std::vector<long long int>& data) const;
std::vector<long long int> read_from_file(const std::string& filename) const;
void write_keys_to_file(const std::string& filename) const;
static std::vector<unsigned char> read_image(const std::string& filename);
static void write_image(const std::string& filename, const std::vector<unsigned char>& data);
```
Esses métodos permitem escrever dados em um arquivo, ler dados de um arquivo e manipular imagens em formato binário. `write_keys_to_file` escreve as chaves pública e privada em um arquivo.

## Uso
Para usar a classe `RSA`, basta incluir o cabeçalho `RSA.hpp` em seu projeto e criar uma instância, passando os limites desejados para a geração das chaves. Em seguida, você pode criptografar e descriptografar imagens, além de realizar operações de arquivo conforme necessário.
