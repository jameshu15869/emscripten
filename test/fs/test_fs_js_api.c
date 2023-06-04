#include <emscripten/emscripten.h>
#include <stdio.h>
#include <sys/stat.h>
#include <assert.h>

int main() {
    /********** test FS.open() **********/
    EM_ASM(
        FS.writeFile('testfile', 'a=1\nb=2\n');
        var readStream = FS.open('testfile', 'r');
        var writeStream = FS.open('testfile', 'w');
        var writePlusStream = FS.open('testfile', 'w+');
        var appendStream = FS.open('testfile', 'a');
#if WASMFS
        assert(readStream >= 0);
        assert(writeStream >= 0);
        assert(writePlusStream >= 0);
        assert(appendStream >= 0);
#else
        assert(readStream && readStream.fd >= 0);
        assert(writeStream && writeStream.fd >= 0);
        assert(writePlusStream && writePlusStream.fd >= 0);
        assert(appendStream && appendStream.fd >= 0);
#endif

        var ex;
        try {
            FS.open('filenothere', 'r');
        } catch(err) {
            ex = err;
        }
        assert(ex.name === "ErrnoError" && ex.errno === 44 /* ENOENT */);

        var createFileNotHere = FS.open('filenothere', 'w+');
#if WASMFS
        assert(createFileNotHere >= 0);
#else
        assert(createFileNotHere && createFileNotHere.fd >= 0);
#endif
    );

    /********** test FS.allocate() **********/
    EM_ASM(
        FS.writeFile("allocatetestfile", 'a=1\nb=2\n');
    );
    struct stat s;
    stat("allocatetestfile", &s);
    assert(s.st_size == 8);

    EM_ASM(
        var stream = FS.open("allocatetestfile", "w");
        FS.allocate(stream, 8, 10);
    );
    stat("allocatetestfile", &s);
    assert(s.st_size == 18);

    EM_ASM(
        var stream = FS.open("allocatetestfile", "w");
        FS.allocate(stream, 0, 4);
    );
    stat("allocatetestfile", &s);
    assert(s.st_size == 4);

    EM_ASM(
        var stream = FS.open("allocatetestfile", "w");
        
        var ex;
        try {
            FS.allocate(stream, 0, -1);
        } catch (err) {
            ex = err;
        }
        assert(ex.name === "ErrnoError" && ex.errno === 28 /* EINVAL */);
    );

    /********** test FS.close() **********/
    EM_ASM(
        FS.writeFile("closetestfile", 'a=1\nb=2\n');
        FS.mkdir("/testdir");
        var file = FS.open("closetestfile", "r");
        var error = FS.close(file);
        assert(!error);

        file = FS.open("/testdir", "r");
        error = FS.close(file);
        assert(!error);

        var ex;
        try {
            FS.close(file);
        } catch(err) {
            ex = err;
        }

        assert(ex.name === "ErrnoError" && ex.errno === 8 /* EBADF */)
    );

    remove("allocatetestfile");

    puts("success");
}
