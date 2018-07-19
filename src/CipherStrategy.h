#pragma once

#include <vector>

class CipherStrategy
{
	using BYTE = unsigned char;

public:
	std::vector<BYTE> decode(const std::vector<BYTE>& inputEncoded)
	{
		return decodeImpl(inputEncoded);
	}
	std::vector<BYTE> encode(const std::vector<BYTE>& inputDecoded)
	{
		return encodeImpl(inputDecoded);
	}

private:
	virtual std::vector<BYTE> decodeImpl(const std::vector<BYTE>& inputEncoded) = 0;
	virtual std::vector<BYTE> encodeImpl(const std::vector<BYTE>& inputDecoded) = 0;
};
