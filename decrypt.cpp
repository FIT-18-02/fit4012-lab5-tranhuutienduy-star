#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include "structures.h"

using namespace std;

/*
 * XOR state với round key
 */
void SubRoundKey(unsigned char *state, unsigned char *roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

/*
 * Inverse MixColumns
 */
void InverseMixColumns(unsigned char *state) {
    unsigned char tmp[16];

    tmp[0]  = mul14[state[0]]  ^ mul11[state[1]]  ^ mul13[state[2]]  ^ mul9[state[3]];
    tmp[1]  = mul9[state[0]]   ^ mul14[state[1]]  ^ mul11[state[2]]  ^ mul13[state[3]];
    tmp[2]  = mul13[state[0]]  ^ mul9[state[1]]   ^ mul14[state[2]]  ^ mul11[state[3]];
    tmp[3]  = mul11[state[0]]  ^ mul13[state[1]]  ^ mul9[state[2]]   ^ mul14[state[3]];

    tmp[4]  = mul14[state[4]]  ^ mul11[state[5]]  ^ mul13[state[6]]  ^ mul9[state[7]];
    tmp[5]  = mul9[state[4]]   ^ mul14[state[5]]  ^ mul11[state[6]]  ^ mul13[state[7]];
    tmp[6]  = mul13[state[4]]  ^ mul9[state[5]]   ^ mul14[state[6]]  ^ mul11[state[7]];
    tmp[7]  = mul11[state[4]]  ^ mul13[state[5]]  ^ mul9[state[6]]   ^ mul14[state[7]];

    tmp[8]  = mul14[state[8]]  ^ mul11[state[9]]  ^ mul13[state[10]] ^ mul9[state[11]];
    tmp[9]  = mul9[state[8]]   ^ mul14[state[9]]  ^ mul11[state[10]] ^ mul13[state[11]];
    tmp[10] = mul13[state[8]]  ^ mul9[state[9]]   ^ mul14[state[10]] ^ mul11[state[11]];
    tmp[11] = mul11[state[8]]  ^ mul13[state[9]]  ^ mul9[state[10]]  ^ mul14[state[11]];

    tmp[12] = mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
    tmp[13] = mul9[state[12]]  ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
    tmp[14] = mul13[state[12]] ^ mul9[state[13]]  ^ mul14[state[14]] ^ mul11[state[15]];
    tmp[15] = mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]]  ^ mul14[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/*
 * ShiftRows ngược
 */
void ShiftRows(unsigned char *state) {
    unsigned char tmp[16];

    tmp[0]  = state[0];
    tmp[1]  = state[13];
    tmp[2]  = state[10];
    tmp[3]  = state[7];

    tmp[4]  = state[4];
    tmp[5]  = state[1];
    tmp[6]  = state[14];
    tmp[7]  = state[11];

    tmp[8]  = state[8];
    tmp[9]  = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];

    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/*
 * Inverse S-box
 */
void SubBytes(unsigned char *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_s[state[i]];
    }
}

/*
 * AES Round
 */
void Round(unsigned char *state, unsigned char *key) {
    SubRoundKey(state, key);
    InverseMixColumns(state);
    ShiftRows(state);
    SubBytes(state);
}

/*
 * Initial Round
 */
void InitialRound(unsigned char *state, unsigned char *key) {
    SubRoundKey(state, key);
    ShiftRows(state);
    SubBytes(state);
}

/*
 * AES Decrypt 1 block
 */
void AESDecrypt(unsigned char *encryptedMessage,
                unsigned char *expandedKey,
                unsigned char *decryptedMessage) {

    unsigned char state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = encryptedMessage[i];
    }

    InitialRound(state, expandedKey + 160);

    for (int i = 8; i >= 0; i--) {
        Round(state, expandedKey + (16 * (i + 1)));
    }

    SubRoundKey(state, expandedKey);

    for (int i = 0; i < 16; i++) {
        decryptedMessage[i] = state[i];
    }
}

int main() {

    cout << "=============================" << endl;
    cout << " 128-bit AES Decryption Tool " << endl;
    cout << "=============================" << endl;

    /*
     * Đọc file message.aes
     */
    ifstream infile("message.aes", ios::binary);

    if (!infile) {
        cerr << "ERROR: Cannot open message.aes" << endl;
        return 1;
    }

    vector<unsigned char> encryptedMessage(
        (istreambuf_iterator<char>(infile)),
        istreambuf_iterator<char>()
    );

    infile.close();

    if (encryptedMessage.empty()) {
        cerr << "ERROR: Empty encrypted file" << endl;
        return 1;
    }

    cout << "Read encrypted message from message.aes" << endl;

    /*
     * Đọc keyfile
     */
    ifstream keyfile("keyfile");

    if (!keyfile) {
        cerr << "ERROR: Cannot open keyfile" << endl;
        return 1;
    }

    string keystr;
    getline(keyfile, keystr);

    keyfile.close();

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
     * Key expansion
     */
    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    /*
     * Kiểm tra block size
     */
    if (encryptedMessage.size() % 16 != 0) {
        cerr << "ERROR: Ciphertext size is not multiple of 16 bytes" << endl;
        return 1;
    }

    vector<unsigned char> decryptedMessage(encryptedMessage.size());

    /*
     * Decrypt từng block
     */
    for (size_t i = 0; i < encryptedMessage.size(); i += 16) {

        AESDecrypt(
            encryptedMessage.data() + i,
            expandedKey,
            decryptedMessage.data() + i
        );
    }

    /*
     * In hex
     */
    cout << "\nDecrypted message (hex):" << endl;

    for (unsigned char c : decryptedMessage) {
        cout << hex
             << setw(2)
             << setfill('0')
             << (int)c
             << " ";
    }

    cout << dec << endl;

    /*
     * In plaintext
     */
    cout << "\nDecrypted message:" << endl;

    for (unsigned char c : decryptedMessage) {
        cout << c;
    }

    cout << endl;

    return 0;
}
