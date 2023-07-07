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

    // mount to a missing directory
    // try {
    //   FS.mount(MEMFS, {}, '/missing');
    // } catch (e) {
    //   ex = e;
    // }
    // assert(ex instanceof FS.ErrnoError && ex.errno === 44); // ENOENT

    console.log("existing");
    // mount to an existing mountpoint
    try {
      FS.mount(MEMFS, {}, '/working');
    } catch (e) {
      ex = e;
    }
    assert(ex instanceof FS.ErrnoError && ex.errno === 10); // EBUSY

    // unmount
    FS.unmount('/working');

    // unmount something that's not mounted
    try {
      FS.unmount('/working');
    } catch (e) {
      ex = e;
    }
    // console.log(ex);

    FS.mkdir('/working/unmountable');
    try {
      FS.unmount('/working/unmountable');
      console.log("good");
    } catch (e) {
      ex = e;
      console.log(ex);
    }
    // console.log(ex);

// #if WASMFS
//     assert(ex instanceof FS.ErrnoError && ex.errno === 44); // ENOENT
// #else
//     assert(ex instanceof FS.ErrnoError && ex.errno === 28); // EINVAL
// #endif

    // mount and unmount again
    FS.mount(MEMFS, {}, '/working');
    FS.unmount('/working');

    // try to read the file from the old mount
    try {
      FS.readFile('/working/waka.txt', { encoding: 'utf8' });
    } catch (e) {
      ex = e;
    }
    // assert(ex instanceof FS.ErrnoError && ex.errno === 44); // ENOENT

    // check the safe file
    contents = FS.readFile('/safe.txt', { encoding: 'utf8' });
    assert(contents === 'abc');
  );

  puts("success");

  return 0;
}
