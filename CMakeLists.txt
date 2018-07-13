cmake_minimum_required(VERSION 3.1)
project(vimcrypt)

add_executable(quicktest main.cpp) # for quick test

add_library(vimcrypt
	src/VimCrypt.cpp include/vimcrypt/VimCrypt.h
	src/cipher/Blowfish.cpp src/cipher/Blowfish.h
	src/CipherStrategy.h
	lib/mbedtls/library/blowfish.c lib/mbedtls/include/mbedtls/blowfish.h
	lib/mbedtls/library/sha256.c lib/mbedtls/include/mbedtls/sha256.h
	lib/mbedtls/library/platform_util.c lib/mbedtls/include/mbedtls/platform_util.h
	)

	#target_compile_definitions(vimcryptA PRIVATE -DMBEDTLS_CIPHER_MODE_CFB)
	
target_include_directories(vimcrypt
	PUBLIC include/
	PRIVATE src/ lib/mbedtls/include/
	)

target_link_libraries(quicktest PRIVATE vimcrypt)
install(TARGETS quicktest RUNTIME DESTINATION bin)
