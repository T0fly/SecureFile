### **程序的正确输入输出示例**
以下是使用该程序进行加密和解密时的完整输入输出示例。假设您有一个名为 `example.docx` 的文件需要加密解密。

---

### **1. 加密文件**
#### **输入**
```plaintext
请输入操作：1. 加密文件 2. 解密文件
1
输入要加密的文件路径：example.docx
```

#### **输出**
```plaintext
密钥已保存到文件：example.key
文件已加密保存到：example.enc
```

#### **说明**
- **生成的文件**：
    1. `example.key`：保存加密密钥的文件。
    2. `example.enc`：加密后的文件。
- **操作**：
    - 程序会读取 `example.docx`，将其加密后保存为 `example.enc`。
    - 程序会自动提取原始文件扩展名（`.docx`），并将其嵌入到加密文件中。

---

### **2. 解密文件**
#### **输入**
```plaintext
请输入操作：1. 加密文件 2. 解密文件
2
输入加密文件路径：example.enc
输入密钥文件路径：example.key
```

#### **输出**
```plaintext
扩展名：.docx
文件已解密保存到：example.docx
```

#### **说明**
- **生成的文件**：
    1. `example.docx`：解密后的文件，与原始文件相同。
- **操作**：
    - 程序会从 `example.enc` 中读取加密数据和原始扩展名（`.docx`）。
    - 使用 `example.key` 提供的密钥解密数据，并恢复文件为 `example.docx`。

---

### **3. 文件生成和结构**
#### **加密后的文件结构（`example.enc`）**
加密文件的头部结构如下：
1. **IV（初始化向量）**：16 字节。
2. **扩展名长度**：4 字节（`size_t` 类型）。
3. **扩展名内容**：变长字符串，例如 `.docx`。
4. **加密数据**：原始文件加密后的数据。

#### **密钥文件（`example.key`）**
密钥文件是二进制文件，保存了 16 字节的 AES 密钥。

---

### **完整交互示例**
#### **第一次运行（加密）**
```plaintext
D:\securefile>securefile.exe
请输入操作：1. 加密文件 2. 解密文件
1
输入要加密的文件路径：example.docx
密钥已保存到文件：example.key
文件已加密保存到：example.enc
```

#### **第二次运行（解密）**
```plaintext
D:\securefile>securefile.exe
请输入操作：1. 加密文件 2. 解密文件
2
输入加密文件路径：example.enc
输入密钥文件路径：example.key
扩展名：.docx
文件已解密保存到：example.docx
```

---

### **程序的注意事项**
1. **文件路径有效性**：
    - 确保输入的文件路径存在且可读写。
    - 输出文件路径的目录应具有写权限。

2. **密钥文件保护**：
    - 如果丢失密钥文件（`example.key`），将无法解密文件。

3. **扩展名嵌入**：
    - 解密时，程序会根据加密文件中存储的扩展名恢复原始文件类型。

---

### **常见问题**
#### **Q1：加密文件路径错误或不存在时的提示？**
**错误输入**：
```plaintext
请输入操作：1. 加密文件 2. 解密文件
1
输入要加密的文件路径：nonexistent.docx
```
**错误输出**：
```plaintext
无法打开源文件：nonexistent.docx
```

#### **Q2：解密时密钥文件错误或不存在？**
**错误输入**：
```plaintext
请输入操作：1. 加密文件 2. 解密文件
2
输入加密文件路径：example.enc
输入密钥文件路径：wrong.key
```
**错误输出**：
```plaintext
无法读取密钥文件：wrong.key
```

#### **Q3：加密文件损坏时的提示？**
如果加密文件头部损坏或被截断：
```plaintext
读取 IV 失败，文件可能已损坏！
```