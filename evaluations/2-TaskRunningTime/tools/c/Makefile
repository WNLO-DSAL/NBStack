CFLAGS_fsync = -DSQLITE_ENABLE_ATOMIC_WRITE -DSQLITE_ENABLE_BATCH_ATOMIC_WRITE -fno-omit-frame-pointer
CFLAGS_datasync = -DSQLITE_ENABLE_ATOMIC_WRITE -DSQLITE_ENABLE_BATCH_ATOMIC_WRITE -DHAVE_FDATASYNC -fno-omit-frame-pointer

LIBS = -lpthread -ldl -lz

all:c_insertTest_fsync c_insertTest_datasync

c_insertTest_fsync:c_insertTest.c
	gcc -o c_insertTest_fsync c_insertTest.c sqlite3.c $(LIBS) $(CFLAGS_fsync)

c_insertTest_datasync:c_insertTest.c
	gcc -o c_insertTest_datasync c_insertTest.c sqlite3.c $(LIBS) $(CFLAGS_datasync)

clean:
	rm -f c_insertTest_fsync c_insertTest_datasync
