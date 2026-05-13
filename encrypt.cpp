#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <cstring> 
#include "structures.h"

using namespace std;
 
/*
 * XOR state với round key
 */
void AddRoundKey(unsigned char *state, unsigned char *roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

/*
 * S-Box substitution
 */
void SubBytes(unsigned char *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = s[state[i]];
    }
}

/*
 * ShiftRows
 */
void ShiftRows(unsigned char *state) {

    unsigned char tmp[16];

    tmp[0]  = state[0];
    tmp[1]  = state[5];
    tmp[2]  = state[10];
    tmp[3]  = state[15];

    tmp[4]  = state[4];
    tmp[5]  = state[9];
    tmp[6]  = state[14];
    tmp[7]  = state[3];

    tmp[8]  = state[8];
    tmp[9]  = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/*
 * MixColumns
 */
void MixColumns(unsigned char *state) {

    unsigned char tmp[16];

    tmp[0]  = mul2[state[0]]  ^ mul3[state[1]]  ^ state[2]  ^ state[3];
    tmp[1]  = state[0]        ^ mul2[state[1]]  ^ mul3[state[2]] ^ state[3];
    tmp[2]  = state[0]        ^ state[1]        ^ mul2[state[2]] ^ mul3[state[3]];
    tmp[3]  = mul3[state[0]]  ^ state[1]        ^ state[2]       ^ mul2[state[3]];

    tmp[4]  = mul2[state[4]]  ^ mul3[state[5]]  ^ state[6]  ^ state[7];
    tmp[5]  = state[4]        ^ mul2[state[5]]  ^ mul3[state[6]] ^ state[7];
    tmp[6]  = state[4]        ^ state[5]        ^ mul2[state[6]] ^ mul3[state[7]];
    tmp[7]  = mul3[state[4]]  ^ state[5]        ^ state[6]       ^ mul2[state[7]];

    tmp[8]  = mul2[state[8]]  ^ mul3[state[9]]  ^ state[10] ^ state[11];
    tmp[9]  = state[8]        ^ mul2[state[9]]  ^ mul3[state[10]] ^ state[11];
    tmp[10] = state[8]        ^ state[9]        ^ mul2[state[10]] ^ mul3[state[11]];
    tmp[11] = mul3[state[8]]  ^ state[9]        ^ state[10]      ^ mul2[state[11]];

    tmp[12] = mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
    tmp[13] = state[12]       ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
    tmp[14] = state[12]       ^ state[13]       ^ mul2[state[14]] ^ mul3[state[15]];
    tmp[15] = mul3[state[12]] ^ state[13]       ^ state[14]      ^ mul2[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/*
 * AES Round
 */
void Round(unsigned char *state, unsigned char *key) {

    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key);
}

/*
 * Final Round
 */
void FinalRound(unsigned char *state, unsigned char *key) {

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key);
}

/*
 * Encrypt 1 block
 */
void AESEncrypt(unsigned char *message,
                unsigned char *expandedKey,
                unsigned char *encryptedMessage) {

    unsigned char state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = message[i];
    }

    AddRoundKey(state, expandedKey);

    for (int i = 0; i < 9; i++) {
        Round(state, expandedKey + (16 * (i + 1)));
    }

    FinalRound(state, expandedKey + 160);

    for (int i = 0; i < 16; i++) {
        encryptedMessage[i] = state[i];
    }
}

int main() {

    cout << "=============================" << endl;
    cout << " 128-bit AES Encryption Tool " << endl;
    cout << "=============================" << endl;

    /*
     * Nhập plaintext
     */
    string message;

    cout << "Enter message to encrypt: ";
    getline(cin, message);

    if (message.empty()) {
        cerr << "ERROR: Empty message" << endl;
        return 1;
    }

    /*
     * PKCS#7 Padding
     */
    int originalLen = message.size();

    int paddingLen = 16 - (originalLen % 16);

    int paddedLen = originalLen + paddingLen;

    vector<unsigned char> paddedMessage(paddedLen);

    for (int i = 0; i < originalLen; i++) {
        paddedMessage[i] = static_cast<unsigned char>(message[i]);
    }

    for (int i = originalLen; i < paddedLen; i++) {
        paddedMessage[i] = static_cast<unsigned char>(paddingLen);
    }

    /*
     * Đọc keyfile
     */
    ifstream infile("keyfile");

    if (!infile) {
        cerr << "ERROR: Cannot open keyfile" << endl;
        return 1;
    }

    string keystr;

    getline(infile, keystr);

    infile.close();

    istringstream hexStream(keystr);

    unsigned char key[16];

    unsigned int value;

    int index = 0;

    while (hexStream >> hex >> value) {

        if (index >= 16) {
            cerr << "ERROR: Key too long" << endl;
            return 1;
        }

        key[index++] = static_cast<unsigned char>(value);
    }

    if (index != 16) {
        cerr << "ERROR: AES-128 key must contain 16 bytes" << endl;
        return 1;
    }

    cout << "Read 128-bit key from keyfile" << endl;

    /*
     * Key Expansion
     */
    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    /*
     * Encrypt
     */
    vector<unsigned char> encryptedMessage(paddedLen);

    for (int i = 0; i < paddedLen; i += 16) {

        AESEncrypt(
            paddedMessage.data() + i,
            expandedKey,
            encryptedMessage.data() + i
        );
    }

    /*
     * In hex
     */
    cout << "\nEncrypted message (hex):" << endl;

    for (unsigned char c : encryptedMessage) {

        cout << hex
             << setw(2)
             << setfill('0')
             << (int)c
             << " ";
    }

    cout << dec << endl;

    /*
     * Ghi binary file
     */
    ofstream outfile("message.aes", ios::binary);

    if (!outfile) {
        cerr << "ERROR: Cannot write message.aes" << endl;
        return 1;
    }

    outfile.write(
        reinterpret_cast<char*>(encryptedMessage.data()),
        encryptedMessage.size()
    );

    outfile.close();

    cout << "\nEncrypted message written to message.aes" << endl;

    return 0;
}
