#pragma once

#include <string>

#include <CipherStrategy.h>

extern "C" {
struct mbedtls_blowfish_context;
}

class Blowfish : public CipherStrategy
{
public:
	Blowfish(const std::string& password, const std::vector<unsigned char>& salt);
	~Blowfish();
	// Blowfish(const std::string& password);

private:
	mbedtls_blowfish_context* _context;

	std::vector<unsigned char> decodeImpl(const std::vector<unsigned char>& inputEncoded) override;
	std::vector<unsigned char> encodeImpl(const std::vector<unsigned char>& inputDecoded) override;

	/**
	 * Convert password to cipher key
	 * @return cipher key
	 **/
	std::vector<unsigned char> saltPassword(const std::string& password,
	                                        const std::vector<unsigned char>& salt) const;
	std::vector<unsigned char> sha256_key(const std::string& key,
	                                      const std::vector<unsigned char>& salt) const;
	std::vector<unsigned char> sha256_key(const std::vector<unsigned char>& key,
	                                      const std::vector<unsigned char>& salt) const;
};
