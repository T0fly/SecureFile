#ifndef COMPLEX_
#define COMPLEX_

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;
namespace fs = std::filesystem;

const size_t KEY_SIZE = 16; // AES-128 ��Կ��С
const size_t IV_SIZE = 16;  // ��ʼ��������С

// ���������Կ�����浽�ļ�
void generateKey(const string& keyFile, unsigned char* key, size_t keySize) {
    if (!RAND_bytes(key, keySize)) {
        cerr << "�����Կ����ʧ�ܣ�" << endl;
        exit(1);
    }

    ofstream outFile(keyFile, ios::binary);
    if (!outFile.is_open()) {
        cerr << "�޷�������Կ�ļ���" << keyFile << endl;
        exit(1);
    }

    outFile.write(reinterpret_cast<const char*>(key), keySize);
    outFile.close();
    cout << "��Կ�ѱ��浽�ļ���" << keyFile << endl;
}

// ����Կ�ļ�������Կ
void loadKey(const string& keyFile, unsigned char* key, size_t keySize) {
    ifstream inFile(keyFile, ios::binary);
    if (!inFile.is_open()) {
        cerr << "�޷���ȡ��Կ�ļ���" << keyFile << endl;
        exit(1);
    }

    inFile.read(reinterpret_cast<char*>(key), keySize);
    if (inFile.gcount() != keySize) {
        cerr << "��Կ�ļ���С��Ч��" << endl;
        exit(1);
    }

    inFile.close();
}

// �����ļ�
void encryptFile(const string& inputFile, const string& outputFile, const string& extFile, const unsigned char* key) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);

    if (!inFile.is_open()) {
        cerr << "�޷���Դ�ļ���" << inputFile << endl;
        exit(1);
    }
    if (!outFile.is_open()) {
        cerr << "�޷����������ļ���" << outputFile << endl;
        exit(1);
    }

    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) {
        cerr << "��� IV ����ʧ�ܣ�" << endl;
        exit(1);
    }

    // д�� IV ��ԭʼ��չ��������ļ�
    outFile.write(reinterpret_cast<const char*>(iv), IV_SIZE);
    if (!outFile.good()) {
        cerr << "д�� IV ʧ�ܣ�" << endl;
        exit(1);
    }

    size_t extLen = extFile.size();
    outFile.write(reinterpret_cast<const char*>(&extLen), sizeof(extLen));
    if (!outFile.good()) {
        cerr << "д����չ������ʧ�ܣ�" << endl;
        exit(1);
    }

    outFile.write(extFile.c_str(), extLen);
    if (!outFile.good()) {
        cerr << "д����չ��ʧ�ܣ�" << endl;
        exit(1);
    }

    // ��ʼ������������
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key, iv);

    vector<unsigned char> buffer(1024);
    vector<unsigned char> encryptedBuffer(buffer.size() + EVP_CIPHER_block_size(EVP_aes_128_cfb()));

    int outLen;
    while (inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        EVP_EncryptUpdate(ctx, encryptedBuffer.data(), &outLen, buffer.data(), bytesRead);
        outFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), outLen);
    }

    EVP_EncryptFinal_ex(ctx, encryptedBuffer.data(), &outLen);
    outFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);

    inFile.close();
    outFile.close();
    cout << "�ļ��Ѽ��ܱ��浽��" << outputFile << endl;
}

// �����ļ�
void decryptFile(const string& inputFile, const string& keyFile) {
    unsigned char key[KEY_SIZE];
    loadKey(keyFile, key, sizeof(key));

    ifstream inFile(inputFile, ios::binary);
    if (!inFile.is_open()) {
        cerr << "�޷��򿪼����ļ���" << inputFile << endl;
        exit(1);
    }

    unsigned char iv[IV_SIZE];
    inFile.read(reinterpret_cast<char*>(iv), IV_SIZE);
    if (inFile.gcount() != IV_SIZE) {
        cerr << "��ȡ IV ʧ�ܣ��ļ��������𻵣�" << endl;
        exit(1);
    }

    size_t extLen;
    inFile.read(reinterpret_cast<char*>(&extLen), sizeof(extLen));
    if (inFile.gcount() != sizeof(extLen) || extLen > 256) {
        cerr << "��ȡ��չ������ʧ�ܻ򳤶Ȳ������ļ��������𻵣�" << endl;
        exit(1);
    }

    string originalExt(extLen, '\0');
    inFile.read(originalExt.data(), extLen);
    if (inFile.gcount() != static_cast<std::streamsize>(extLen)) {
        cerr << "��ȡ��չ��ʧ�ܣ��ļ��������𻵣�" << endl;
        exit(1);
    }

    string outputFile = fs::path(inputFile).replace_extension(originalExt).string();
    ofstream outFile(outputFile, ios::binary);
    if (!outFile.is_open()) {
        cerr << "�޷����������ļ���" << outputFile << endl;
        exit(1);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key, iv);

    vector<unsigned char> buffer(1024);
    vector<unsigned char> decryptedBuffer(buffer.size() + EVP_CIPHER_block_size(EVP_aes_128_cfb()));

    int outLen;
    while (inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        EVP_DecryptUpdate(ctx, decryptedBuffer.data(), &outLen, buffer.data(), bytesRead);
        outFile.write(reinterpret_cast<const char*>(decryptedBuffer.data()), outLen);
    }

    EVP_DecryptFinal_ex(ctx, decryptedBuffer.data(), &outLen);
    outFile.write(reinterpret_cast<const char*>(decryptedBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);

    inFile.close();
    outFile.close();
    cout << "�ļ��ѽ��ܱ��浽��" << outputFile << endl;
}

int main() {
    string inputFile, keyFile;

    cout << "�����������1. �����ļ� 2. �����ļ�\n";
    int choice;
    cin >> choice;

    if (choice == 1) {
        cout << "����Ҫ���ܵ��ļ�·����";
        cin >> inputFile;

        string outputFile = fs::path(inputFile).replace_extension(".enc").string();
        string keyFile = fs::path(inputFile).replace_extension(".key").string();
        string extFile = fs::path(inputFile).extension().string();

        unsigned char key[KEY_SIZE];
        generateKey(keyFile, key, sizeof(key));
        encryptFile(inputFile, outputFile, extFile, key);
    } else if (choice == 2) {
        cout << "��������ļ�·����";
        cin >> inputFile;
        cout << "������Կ�ļ�·����";
        cin >> keyFile;

        decryptFile(inputFile, keyFile);
    } else {
        cerr << "��Чѡ�" << endl;
    }

    return 0;
}

#endif
