#include "vimcrypt/VimCrypt.h"

#include <cassert>
#include <iterator>
#include <sstream>

VimCrypt::VimCrypt(std::istream& data)
{
	std::noskipws(data); // prevent from skipping whitechars

	std::copy(std::istream_iterator<char>(data),
	          std::istream_iterator<char>(),
	          std::back_inserter(_data));

	try
	{
		std::string tmpData;
		std::copy(_data.begin(),
		          _data.begin() + std::min(_data.size(), _header.size()),
		          std::back_inserter(tmpData));
		std::istringstream tmpStream{tmpData};
		_header = readHeader(tmpStream);
		// If everything went well we can erase header from data
		_data.erase(_data.begin(), _data.begin() + _header.size());
	}
	catch(const std::invalid_argument& ex)
	{
		// ignore, probably plaintext not encoded
	}
}

VimCrypt::Header::Header()
{
	_magic.fill('\0');
	_salt.fill('\0');
	_IV.fill('\0');
}

constexpr std::size_t VimCrypt::Header::size() const noexcept
{
	return _magic.max_size() + _salt.max_size() + _IV.max_size();
}

VimCrypt::Header VimCrypt::readHeader(std::istream& data)
{
	Header header;
	auto& magic = header._magic;
	auto& salt = header._salt;
	auto& IV = header._IV;

	if(data.readsome(magic.data(), magic.max_size()) != magic.max_size())
	{
		throw std::invalid_argument("Invalid header - can't read magic");
	}

	header._encode = forName(std::string{magic.begin(), magic.end()});
	if(header._encode == Encoded::none)
	{
		throw std::invalid_argument("Invalid header - none");
	}

	if(data.readsome(salt.data(), salt.max_size()) != salt.max_size())
	{
		throw std::invalid_argument("Invalid header - can't read salt");
	}

	if(data.readsome(IV.data(), IV.max_size()) != IV.max_size())
	{
		throw std::invalid_argument("Invalid header - can't read IV vector");
	}
	return header;
}

std::vector<char> VimCrypt::decode(const std::string& password)
{
	return {};
}

std::vector<char> VimCrypt::encode(const std::string& password)
{
	throw std::runtime_error("Not implemented");
}

VimCrypt::Encoded VimCrypt::forName(const std::string& name)
{
	if(name == "VimCrypt~01!")
	{
		return Encoded::zip;
	}
	if(name == "VimCrypt~02!")
	{
		return Encoded::blowfish;
	}
	if(name == "VimCrypt~03!")
	{
		return Encoded::blowfish2;
	}
	return Encoded::none;
}

std::ostream& operator<<(std::ostream& stream, const VimCrypt& vimCrypt)
{
	stream << "Magic:" << vimCrypt._header._magic.data()
	       << ": salt:" << vimCrypt._header._salt.data() << ": IV:" << vimCrypt._header._IV.data()
	       << ":\nEncoded with: " << vimCrypt._header._encode << "\nData:";

	std::copy(vimCrypt._data.begin(), vimCrypt._data.end(), std::ostream_iterator<char>(stream));
	return stream;
}

std::ostream& operator<<(std::ostream& stream, const VimCrypt::Encoded& encode)
{
	switch(encode)
	{
	case VimCrypt::Encoded::none:
		stream << "none";
		break;
	case VimCrypt::Encoded::zip:
		stream << "zip";
		break;
	case VimCrypt::Encoded::blowfish:
		stream << "blowfish";
		break;
	case VimCrypt::Encoded::blowfish2:
		stream << "blowfish2";
		break;
	default:
		stream << "todo implement encode name";
	}
	return stream;
}
