#include <fstream>
#include <iostream>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <vimcrypt/VimCrypt.h>

int main(int argc, char** argv)
{
	std::cout << "Hello, world!" << std::endl;

	char cwd[1024];
	if(getcwd(cwd, sizeof(cwd)) != NULL)
	{
		fprintf(stdout, "Current working dir: %s\n", cwd);
	}
	else
	{
		perror("getcwd() error");
	}

	std::fstream file("test/input/test.encoded", std::fstream::in);
	if(file.is_open() == false)
	{
		throw "File not open!";
	}

	// std::cout << file.rdbuf() << std::endl;

	VimCrypt crypt{file};

	std::cout << crypt << std::endl;
	std::cout << "Decoded:" << std::endl;
	std::cout << crypt.decodeAsString("test") << std::endl;

	return 0;
}
