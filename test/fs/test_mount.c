/*
 * Copyright 2014 The Emscripten Authors.  All rights reserved.
 * Emscripten is available under two separate licenses, the MIT license and the
 * University of Illinois/NCSA Open Source License.  Both these licenses can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <stdio.h>
#include <emscripten.h>
#include <fcntl.h>

int main() {
  EM_ASM(
    var ex;
    var contents;

    // write a file that should be unaffected by this process
    FS.writeFile('/safe.txt', 'abc');

    // mount it the first time
    FS.mkdir('/working');
    FS.mount(MEMFS, {}, '/working');
    FS.writeFile('/working/waka.txt', 'az');

    // check the waka file
    contents = FS.readFile('/working/waka.txt', { encoding: 'utf8' });
    assert(contents === 'az');

#if !defined(WASMFS)
    // The legacy API requires a mount directory to exist, while WasmFS will create the directory.
    try {
      FS.mount(MEMFS, {}, '/missing');
    } catch (e) {
      ex = e;
    }
    assert(ex instanceof FS.ErrnoError && ex.errno === 44); // ENOENT
#endif

#if WASMFS
    // WasmFS will throw an error if a directory to mount to is not empty, while the legacy API will not.
    try {
      FS.mkdir("/test");
      FS.writeFile("/test/hi.txt", "abc");
      FS.mount(MEMFS, {}, '/test');
    } catch (e) {
      ex = e;
    }
    assert(ex instanceof FS.ErrnoError && ex.errno === 55); // ENOTEMPTY
#endif

    // mount to an existing mountpoint
    try {
      FS.mount(MEMFS, {}, '/working');
    } catch (e) {
      ex = e;
    }
    assert(ex instanceof FS.ErrnoError && ex.errno === 10); // EBUSY

    // attempt to unmount a nonmountopint directory inside a mountpoint
    FS.mkdir('/working/unmountable');
    try {
      FS.unmount('/working/unmountable');
    } catch (e) {
      ex = e;
    }
    assert(ex instanceof FS.ErrnoError && ex.errno === 28); // EINVAL

    // unmount
    FS.unmount('/working');

    // unmount something that's not mounted
    try {
      FS.unmount('/working');
    } catch (e) {
      ex = e;
    }
    assert(ex instanceof FS.ErrnoError && ex.errno === 28); // EINVAL

    // mount and unmount again
    FS.mount(MEMFS, {}, '/working');
    FS.unmount('/working');

    // try to read the file from the old mount
    try {
      FS.readFile('/working/waka.txt', { encoding: 'utf8' });
    } catch (e) {
      ex = e;
    }
#if !defined(WASMFS)
      // WasmFS readFile aborts on failure, instead throwing an ErrnoError.
      assert(ex instanceof FS.ErrnoError && ex.errno === 44); // ENOENT
#else
      assert(ex);
#endif

    // check the safe file
    contents = FS.readFile('/safe.txt', { encoding: 'utf8' });
    assert(contents === 'abc');

#if WASMFS
    FS.mount(JS_FILE, {}, "/jsfile");
    FS.writeFile("/jsfile/jsfile.txt", "a=1");
    assert(FS.readFile("/jsfile/jsfile.txt", { encoding: 'utf8' }) === 'a=1');
#endif
  );

  puts("success");

  return 0;
}
