#pragma once
#include<iostream>
#include"rsa_class/rsa.hpp"
#include<vector>
#include<Windows.h>

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
WORD originalAttrs;

void menu (void);
void gerar_chaves (void);
void criptografar (long long int& key, long long int& n, std::string& nome_arquivo_original, std::string& nome_arquivo_final);
void decriptografar (long long int& key, long long int& n, std::string& nome_arquivo_original, std::string& nome_arquivo_final);
void reset_config_console(void);
void set_console_sucess (void);
void set_console_error (void);
