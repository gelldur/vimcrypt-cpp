#include "Blowfish.h"

#include <algorithm>
#include <stdexcept>
#include <string>

#include <mbedtls/blowfish.h>
#include <mbedtls/sha256.h>

#include <Utils.h>

Blowfish::Blowfish(const std::string& password,
                   const std::vector<unsigned char>& salt,
                   std::vector<unsigned char> IV)
    : _context(new mbedtls_blowfish_context)
    , _IV(std::move(IV))
{
	mbedtls_blowfish_init(_context);
	auto cipherKey = saltPassword(password, salt);

	int error = mbedtls_blowfish_setkey(_context, &cipherKey.at(0), cipherKey.size() * 8);
	if(error != 0)
	{
		throw std::runtime_error{std::string{"Blowfish invalid key:"} + std::to_string(error)};
	}

	if(_IV.size() != MBEDTLS_BLOWFISH_BLOCKSIZE)
	{
		throw std::runtime_error{"Incorrect size!"};
	}
}

Blowfish::~Blowfish()
{
	mbedtls_blowfish_free(_context);
	delete _context;
	_context = nullptr;
}

std::vector<unsigned char> Blowfish::wordSwap(std::vector<unsigned char> data) const
{
	// Swap byte order in each DWORD
	const int DWORD = 4;
	for(int i = DWORD; i <= data.size(); i += DWORD)
	{
		std::reverse(data.begin() + i - DWORD, data.begin() + i);
	}
	if(data.size() % DWORD != 0)
	{
		std::reverse(data.end() - (data.size() % DWORD), data.end());
	}
	return data;
}

std::vector<unsigned char> Blowfish::encryptECB(std::vector<unsigned char> data)
{
	data = wordSwap(data);
	std::vector<unsigned char> outputData(data.size(), 0);
	int error = mbedtls_blowfish_crypt_ecb(
	    _context, MBEDTLS_BLOWFISH_ENCRYPT, &data.at(0), &outputData.at(0));

	if(error != 0)
	{
		throw std::runtime_error{std::string{"Blowfish decrypt failed with error:"} +
		                         std::to_string(error)};
	}

	return wordSwap(outputData);
}

std::vector<unsigned char> Blowfish::decodeImpl(const std::vector<unsigned char>& inputEncoded)
{
	std::vector<unsigned char> outputData;
	outputData.reserve(inputEncoded.size());

	auto xorR = encryptECB(_IV);

	for(unsigned i = 0; i < inputEncoded.size(); ++i)
	{
		if(i >= 64 && (i % 8) == 0)
		{
			xorR = encryptECB(std::vector<unsigned char>{inputEncoded.begin() + (i - 64),
			                                             inputEncoded.begin() + (i - 64 + 8)});
		}
		outputData.push_back(xorR.at(i % 8) ^ inputEncoded.at(i));
	}
	return outputData;
}

std::vector<unsigned char> Blowfish::encodeImpl(const std::vector<unsigned char>& inputDecoded)
{
	throw std::runtime_error{"Not implemented"};
}

std::vector<unsigned char> Blowfish::saltPassword(const std::string& password,
                                                  const std::vector<unsigned char>& salt) const
{
	// Process key 1001 times. @see http://en.wikipedia.org/wiki/Key_strengthening.
	std::vector<unsigned char> key = sha256_key(password, salt);

	for(int i = 0; i < 1000; ++i)
	{
		key = sha256_key(Utils::binaryToHex(key), salt);
	}
	return key;
}

std::vector<unsigned char> Blowfish::sha256_key(const std::string& key,
                                                const std::vector<unsigned char>& salt) const
{
	return sha256_key(std::vector<unsigned char>{key.begin(), key.end()}, salt);
}

std::vector<unsigned char> Blowfish::sha256_key(const std::vector<unsigned char>& key,
                                                const std::vector<unsigned char>& salt) const
{
	mbedtls_sha256_context context;
	mbedtls_sha256_init(&context);

	mbedtls_sha256_starts_ret(&context, 0);

	mbedtls_sha256_update_ret(&context, &key.at(0), key.size());
	mbedtls_sha256_update_ret(&context, &salt.at(0), salt.size());

	unsigned char output[32];
	mbedtls_sha256_finish_ret(&context, output);

	mbedtls_sha256_free(&context);

	return {output, output + sizeof(output) / sizeof(output[0])};
}
