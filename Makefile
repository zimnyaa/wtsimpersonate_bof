BOFNAME := wtsimpersonate
LIBINCLUDE := 
CC_x64 := x86_64-w64-mingw32-gcc

all:
	$(CC_x64) -o $(BOFNAME).x64.o -Os -c entry.c
wtf:
	$(CC_x64) -o wtf.x64.o -Os -c wtf.c
