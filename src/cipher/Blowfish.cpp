#include "Blowfish.h"

#include <stdexcept>
#include <string>

#include <mbedtls/blowfish.h>
#include <mbedtls/sha256.h>

Blowfish::Blowfish(const std::string& password)
{
	_context = new mbedtls_blowfish_context;

	mbedtls_blowfish_init(_context);

	std::vector<unsigned char> salt{0, 1, 2, 3, 4, 5, 6, 7};
	auto cipherKey = saltPassword(password, salt);

	mbedtls_blowfish_setkey(_context, &cipherKey.at(0), cipherKey.size());
}

Blowfish::~Blowfish()
{
	mbedtls_blowfish_free(_context);
	delete _context;
	_context = nullptr;
}

std::vector<unsigned char> Blowfish::decodeImpl(const std::vector<unsigned char>& inputEncoded)
{
	std::vector<unsigned char> iv{0, 1, 2, 3, 4, 5, 6, 7};
	std::vector<unsigned char> outputData(inputEncoded.size(), 0);

	std::size_t ivOffset = 0; // dummy not used
	int error = mbedtls_blowfish_crypt_cfb64(_context,
	                                         MBEDTLS_BLOWFISH_DECRYPT,
	                                         inputEncoded.size(),
	                                         &ivOffset,
	                                         &iv.at(0),
	                                         &inputEncoded.at(0),
	                                         &outputData.at(0));
	if(error != 0)
	{
		throw std::runtime_error{std::string{"Blowfish decrypt failed with error:"} +
		                         std::to_string(error)};
	}

	return outputData;
}

std::vector<unsigned char> Blowfish::encodeImpl(const std::vector<unsigned char>& inputDecoded)
{
	return {};
}

std::vector<unsigned char> Blowfish::saltPassword(const std::string& password,
                                                  const std::vector<unsigned char>& salt) const
{
	// Process key 1001 times. @see http://en.wikipedia.org/wiki/Key_strengthening.
	std::vector<unsigned char> key =
	    sha256_key(std::vector<unsigned char>{password.begin(), password.end()}, salt);
	for(int i = 0; i < 1000; ++i)
	{
		key = sha256_key(key, salt);
	}
	return key;
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
