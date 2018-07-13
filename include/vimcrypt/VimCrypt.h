#pragma once

#include <array>
#include <istream>
#include <ostream>
#include <vector>

class VimCrypt
{
public:
	VimCrypt(std::istream& data);

	std::vector<char> decode(const std::string& password);
	std::vector<char> encode(const std::string& password);

	enum class Encoded
	{
		none,
		zip, // VimCrypt~01!
		blowfish, // VimCrypt~02!
		blowfish2, // VimCrypt~03!
	};
	static Encoded forName(const std::string& name);

	struct Header
	{
		/**
		 *  File header
		 *  +------------+--------+--------+
		 *  |   Magic    |  Salt  |   IV   |
		 *  +------------+--------+--------+
		 *  |VimCrypt~02!|01234567|01234567|
		 *  +------------+--------+--------+
		 **/
		std::array<char, 12> magic;
		std::array<char, 8> salt;
		std::array<char, 8> IV;

		Encoded encode = Encoded::none;

		Header();

		/**
		 * @return header size in bytes
		 * */
		constexpr std::size_t size() const noexcept;
	};
	static Header readHeader(std::istream& data);

	friend std::ostream& operator<<(std::ostream& stream, const VimCrypt& vimCrypt);
	friend std::ostream& operator<<(std::ostream& stream, const VimCrypt::Encoded& encoded);

private:
	Header _header;
	std::vector<char> _data;
};
