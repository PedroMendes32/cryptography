#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <random>

class RSA final
{
private:
    long long int public_key;
    long long int private_key;
    long long int n;

    bool is_prime(long long int n) const;
    long long int generate_prime(long long int limite_inferior, long long int limite_superior, std::mt19937& rng) const;
    long long int gcd(long long int a, long long int b) const;
    long long int mod_inverse(long long int a, long long int m) const;
    long long int mod_pow(long long int base, long long int exponent, long long int modulus) const;

public:
    RSA(void) = delete;
    explicit RSA(long long int limite_inferior, long long int limite_superior);

    inline long long int get_n(void) const;
    inline long long int get_public_key(void) const;
    inline long long int get_private_key(void) const;
    inline void set_n(const long long int& n);
    inline void set_public_key(const long long int& public_key);
    inline void set_private_key(const long long int& private_key);

    std::vector<long long int> encrypt(const std::vector<long long int>& data) const;
    std::vector<long long int> decrypt(const std::vector<long long int>& encrypted_data) const;
    void write_to_file(const std::string& filename, const std::vector<long long int>& data) const;
    std::vector<long long int> read_from_file(const std::string& filename) const;
    inline void print_public_key() const;
    inline void print_private_key() const;
    void write_keys_to_file(const std::string& filename) const;
    static std::vector<unsigned char> read_image(const std::string& filename);
    static void write_image(const std::string& filename, const std::vector<unsigned char>& data);
};

