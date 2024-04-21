#pragma once
#include<iostream>
#include"rsa_class/rsa.hpp"
#include<vector>

void menu (void);
void gerar_chaves (void);
void criptografar (long long int& key, long long int& n, std::string& nome_arquivo_original, std::string& nome_arquivo_final);
void decriptografar (long long int& key, long long int& n, std::string& nome_arquivo_original, std::string& nome_arquivo_final);

