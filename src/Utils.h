#pragma once

#include <iterator>
#include <string>

namespace Utils
{
template<class Container> std::string binaryToHex(const Container& data)
{
	constexpr char hexmap[] = {
	    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	const auto size = std::distance(std::begin(data), std::end(data));

	std::string text(size * 2, ' ');
	for(int i = 0; i < size; ++i)
	{
		text[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
		text[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return text;
}
}
