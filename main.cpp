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

const size_t KEY_SIZE = 16; // AES-128 密钥大小
const size_t IV_SIZE = 16;  // 初始化向量大小

// 生成随机密钥并保存到文件
void generateKey(const string& keyFile, unsigned char* key, size_t keySize) {
    if (!RAND_bytes(key, keySize)) {
        cerr << "随机密钥生成失败！" << endl;
        exit(1);
    }

    ofstream outFile(keyFile, ios::binary);
    if (!outFile.is_open()) {
        cerr << "无法保存密钥文件：" << keyFile << endl;
        exit(1);
    }

    outFile.write(reinterpret_cast<const char*>(key), keySize);
    outFile.close();
    cout << "密钥已保存到文件：" << keyFile << endl;
}

// 从密钥文件加载密钥
void loadKey(const string& keyFile, unsigned char* key, size_t keySize) {
    ifstream inFile(keyFile, ios::binary);
    if (!inFile.is_open()) {
        cerr << "无法读取密钥文件：" << keyFile << endl;
        exit(1);
    }

    inFile.read(reinterpret_cast<char*>(key), keySize);
    if (inFile.gcount() != keySize) {
        cerr << "密钥文件大小无效！" << endl;
        exit(1);
    }

    inFile.close();
}

// 加密文件
void encryptFile(const string& inputFile, const string& outputFile, const string& extFile, const unsigned char* key) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);

    if (!inFile.is_open()) {
        cerr << "无法打开源文件：" << inputFile << endl;
        exit(1);
    }
    if (!outFile.is_open()) {
        cerr << "无法创建加密文件：" << outputFile << endl;
        exit(1);
    }

    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) {
        cerr << "随机 IV 生成失败！" << endl;
        exit(1);
    }

    // 写入 IV 和原始扩展名到输出文件
    outFile.write(reinterpret_cast<const char*>(iv), IV_SIZE);
    if (!outFile.good()) {
        cerr << "写入 IV 失败！" << endl;
        exit(1);
    }

    size_t extLen = extFile.size();
    outFile.write(reinterpret_cast<const char*>(&extLen), sizeof(extLen));
    if (!outFile.good()) {
        cerr << "写入扩展名长度失败！" << endl;
        exit(1);
    }

    outFile.write(extFile.c_str(), extLen);
    if (!outFile.good()) {
        cerr << "写入扩展名失败！" << endl;
        exit(1);
    }

    // 初始化加密上下文
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
    cout << "文件已加密保存到：" << outputFile << endl;
}

// 解密文件
void decryptFile(const string& inputFile, const string& keyFile) {
    unsigned char key[KEY_SIZE];
    loadKey(keyFile, key, sizeof(key));

    ifstream inFile(inputFile, ios::binary);
    if (!inFile.is_open()) {
        cerr << "无法打开加密文件：" << inputFile << endl;
        exit(1);
    }

    unsigned char iv[IV_SIZE];
    inFile.read(reinterpret_cast<char*>(iv), IV_SIZE);
    if (inFile.gcount() != IV_SIZE) {
        cerr << "读取 IV 失败，文件可能已损坏！" << endl;
        exit(1);
    }

    size_t extLen;
    inFile.read(reinterpret_cast<char*>(&extLen), sizeof(extLen));
    if (inFile.gcount() != sizeof(extLen) || extLen > 256) {
        cerr << "读取扩展名长度失败或长度不合理，文件可能已损坏！" << endl;
        exit(1);
    }

    string originalExt(extLen, '\0');
    inFile.read(originalExt.data(), extLen);
    if (inFile.gcount() != static_cast<std::streamsize>(extLen)) {
        cerr << "读取扩展名失败，文件可能已损坏！" << endl;
        exit(1);
    }

    string outputFile = fs::path(inputFile).replace_extension(originalExt).string();
    ofstream outFile(outputFile, ios::binary);
    if (!outFile.is_open()) {
        cerr << "无法创建解密文件：" << outputFile << endl;
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
    cout << "文件已解密保存到：" << outputFile << endl;
}

int main() {
    string inputFile, keyFile;

    cout << "请输入操作：1. 加密文件 2. 解密文件\n";
    int choice;
    cin >> choice;

    if (choice == 1) {
        cout << "输入要加密的文件路径：";
        cin >> inputFile;

        string outputFile = fs::path(inputFile).replace_extension(".enc").string();
        string keyFile = fs::path(inputFile).replace_extension(".key").string();
        string extFile = fs::path(inputFile).extension().string();

        unsigned char key[KEY_SIZE];
        generateKey(keyFile, key, sizeof(key));
        encryptFile(inputFile, outputFile, extFile, key);
    } else if (choice == 2) {
        cout << "输入加密文件路径：";
        cin >> inputFile;
        cout << "输入密钥文件路径：";
        cin >> keyFile;

        decryptFile(inputFile, keyFile);
    } else {
        cerr << "无效选项！" << endl;
    }

    return 0;
}

#endif
