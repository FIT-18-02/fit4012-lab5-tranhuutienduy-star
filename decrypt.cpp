/* decrypt.cpp
 * Performs decryption using AES 128-bit
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structures.h"

using namespace std;

/* Used in Round() and serves as the final round during decryption
 * SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 */
void SubRoundKey(unsigned char * state, unsigned char * roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
 * Unmixes the columns by reversing the effect of MixColumns in encryption
 */
void InverseMixColumns(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

// Shifts rows right for decryption
void ShiftRows(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	tmp[8] = state[8];
	tmp[9] = state[5];
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

/* Perform substitution using inverse S-box */
void SubBytes(unsigned char * state) {
	for (int i = 0; i < 16; i++) {
		state[i] = inv_s[state[i]];
	}
}

/* AES round for decryption */
void Round(unsigned char * state, unsigned char * key) {
	SubRoundKey(state, key);
	InverseMixColumns(state);
	ShiftRows(state);
	SubBytes(state);
}

/* Initial round without InverseMixColumns */
void InitialRound(unsigned char * state, unsigned char * key) {
	SubRoundKey(state, key);
	ShiftRows(state);
	SubBytes(state);
}

/* AES decryption function */
void AESDecrypt(unsigned char * encryptedMessage,
	unsigned char * expandedKey,
	unsigned char * decryptedMessage)
{
	unsigned char state[16];

	for (int i = 0; i < 16; i++) {
		state[i] = encryptedMessage[i];
	}

	InitialRound(state, expandedKey + 160);

	int numberOfRounds = 9;

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

	// Read encrypted file
	ifstream infile("message.aes", ios::binary | ios::ate);

	if (!infile.is_open()) {
		cout << "Unable to open message.aes" << endl;
		return 1;
	}

	streamsize size = infile.tellg();
	infile.seekg(0, ios::beg);

	unsigned char* encryptedMessage = new unsigned char[size];

	if (!infile.read((char*)encryptedMessage, size)) {
		cout << "Failed to read encrypted file" << endl;
		delete[] encryptedMessage;
		return 1;
	}

	infile.close();

	cout << "Read encrypted message from message.aes" << endl;

	// Read key
	string keystr;

	ifstream keyfile;
	keyfile.open("keyfile", ios::in | ios::binary);

	if (keyfile.is_open()) {
		getline(keyfile, keystr);
		cout << "Read key from keyfile" << endl;
		keyfile.close();
	}
	else {
		cout << "Unable to open keyfile" << endl;
		delete[] encryptedMessage;
		return 1;
	}

	istringstream hex_chars_stream(keystr);

	unsigned char key[16];

	int i = 0;
	unsigned int c;

	while (hex_chars_stream >> hex >> c) {
		key[i] = c;
		i++;
	}

	unsigned char expandedKey[176];

	KeyExpansion(key, expandedKey);

	int messageLen = (int)size;

	unsigned char* decryptedMessage = new unsigned char[messageLen];

	for (int i = 0; i < messageLen; i += 16) {
		AESDecrypt(encryptedMessage + i,
			expandedKey,
			decryptedMessage + i);
	}

	cout << "Decrypted message in hex:" << endl;

	for (int i = 0; i < messageLen; i++) {
		cout << hex << (int)decryptedMessage[i] << " ";
	}

	cout << endl;

	cout << "Decrypted message: ";

	for (int i = 0; i < messageLen; i++) {
		if (decryptedMessage[i] != 0) {
			cout << decryptedMessage[i];
		}
	}

	cout << endl;

	delete[] encryptedMessage;
	delete[] decryptedMessage;

	return 0;
}
