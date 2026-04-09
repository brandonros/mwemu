CC_NATIVE   = cc
CC_LINUX64  = x86_64-unknown-linux-gnu-gcc
CC_LINARM64 = aarch64-unknown-linux-gnu-gcc
CC_WINX64   = x86_64-w64-mingw32-clang
CC_WINARM64 = aarch64-w64-mingw32-clang

SRC = main.c

all: hello-mac-arm64 hello-linux-x64 hello-linux-arm64 hello-win-x64.exe hello-win-arm64.exe

hello-mac-arm64: $(SRC)
	$(CC_NATIVE) $(SRC) -o $@

hello-linux-x64: $(SRC)
	$(CC_LINUX64) $(SRC) -o $@

hello-linux-arm64: $(SRC)
	$(CC_LINARM64) $(SRC) -o $@

hello-win-x64.exe: $(SRC)
	$(CC_WINX64) $(SRC) -o $@

hello-win-arm64.exe: $(SRC)
	$(CC_WINARM64) $(SRC) -o $@

clean:
	rm -f hello-mac-arm64 hello-linux-x64 hello-linux-arm64 hello-win-x64.exe hello-win-arm64.exe

.PHONY: all clean