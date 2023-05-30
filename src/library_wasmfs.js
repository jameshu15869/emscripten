/**
 * @license
 * Copyright 2022 The Emscripten Authors
 * SPDX-License-Identifier: MIT
 */

mergeInto(LibraryManager.library, {
  $wasmFSPreloadedFiles: [],
  $wasmFSPreloadedDirs: [],
  $FS__postset: `
FS.createPreloadedFile = FS_createPreloadedFile;
`,
  $FS__deps: [
    '$wasmFSPreloadedFiles',
    '$wasmFSPreloadedDirs',
    '$PATH',
    '$stringToNewUTF8',
    '$stringToUTF8OnStack',
    '$withStackSave',
    '$readI53FromI64',
    '$FS_createPreloadedFile',
    '$FS_getMode',
#if FORCE_FILESYSTEM
    '$FS_modeStringToFlags',
#endif
  ],
  $FS : {
    createDataFile: (parent, name, data, canRead, canWrite, canOwn) => {
      // Data files must be cached until the file system itself has been initialized.
      var mode = FS_getMode(canRead, canWrite);
      var pathName = name ? parent + '/' + name : parent;
      wasmFSPreloadedFiles.push({pathName: pathName, fileData: data, mode: mode});
    },
    createPath: (parent, path, canRead, canWrite) => {
      // Cache file path directory names.
      var parts = path.split('/').reverse();
      while (parts.length) {
        var part = parts.pop();
        if (!part) continue;
        var current = PATH.join2(parent, part);
        wasmFSPreloadedDirs.push({parentPath: parent, childName: part});
        parent = current;
      }
      return current;
    },
    readFile: (path, opts = {}) => {
      opts.encoding = opts.encoding || 'binary';
      if (opts.encoding !== 'utf8' && opts.encoding !== 'binary') {
        throw new Error('Invalid encoding type "' + opts.encoding + '"');
      }

      var pathName = stringToNewUTF8(path);

      // Copy the file into a JS buffer on the heap.
      var buf = __wasmfs_read_file(pathName);
      // The signed integer length resides in the first 8 bytes of the buffer.
      var length = {{{ makeGetValue('buf', '0', 'i53') }}};

      // Default return type is binary.
      // The buffer contents exist 8 bytes after the returned pointer.
      var ret = new Uint8Array(HEAPU8.subarray(buf + 8, buf + 8 + length));
      if (opts.encoding === 'utf8') {
        ret = UTF8ArrayToString(ret, 0);
      }

      _free(pathName);
      _free(buf);
      return ret;
    },
    cwd: () => {
      // TODO: Remove dependency on FS.cwd().
      // User code should not be using FS.cwd().
      // For file preloading, cwd should be '/' to begin with.
      return '/';
    },

#if FORCE_FILESYSTEM
    // Full JS API support
    mkdir: (path, mode) => {
      return withStackSave(() => {
        mode = mode !== undefined ? mode : 511 /* 0777 */;
        var buffer = stringToUTF8OnStack(path);
        return __wasmfs_mkdir({{{ to64('buffer') }}}, mode);
      });
    },
    // TODO: mkdirTree
    // TDOO: rmdir
    rmdir: (path) => {
      return withStackSave(() => {
        var buffer = stringToUTF8OnStack(path);
        return __wasmfs_rmdir(buffer);
      })
    },
    // TODO: open
    open: (path, flags, mode) => {
      flags = typeof flags == 'string' ? FS_modeStringToFlags(flags) : flags;
      mode = typeof mode == 'undefined' ? 438 /* 0666 */ : mode;
      return withStackSave(() => {
        var buffer = stringToUTF8OnStack(path);
        return __wasmfs_open({{{ to64('buffer') }}}, flags, mode);
      })
    },
    // TODO: create
    // TODO: close
    unlink: (path) => {
      return withStackSave(() => {
        var buffer = stringToUTF8OnStack(path);
        return __wasmfs_unlink(buffer);
      });
    },
    chdir: (path) => {
      return withStackSave(() => {
        var buffer = stringToUTF8OnStack(path);
        return __wasmfs_chdir(buffer);
      });
    },
    // TODO: read
    // TODO: write
    // TODO: allocate
    // TODO: mmap
    // TODO: msync
    // TODO: munmap
    writeFile: (path, data) => {
      return withStackSave(() => {
        var pathBuffer = stringToUTF8OnStack(path);
        if (typeof data == 'string') {
          var buf = new Uint8Array(lengthBytesUTF8(data) + 1);
          var actualNumBytes = stringToUTF8Array(data, buf, 0, buf.length);
          data = buf.slice(0, actualNumBytes);
        }
        var dataBuffer = _malloc(data.length);
#if ASSERTIONS
        assert(dataBuffer);
#endif
        for (var i = 0; i < data.length; i++) {
          {{{ makeSetValue('dataBuffer', 'i', 'data[i]', 'i8') }}};
        }
        var ret = __wasmfs_write_file(pathBuffer, dataBuffer, data.length);
        _free(dataBuffer);
        return ret;
      });
    },
    symlink: (target, linkpath) => {
      return withStackSave(() => {
        var targetBuffer = stringToUTF8OnStack(target);
        var linkpathBuffer = stringToUTF8OnStack(linkpath);
        return __wasmfs_symlink(targetBuffer, linkpathBuffer);
      });
    },
    // TODO: readlink
    // TODO: stat
    stat: (path) => {
      // return withStackSave(() => {
      //   var pathBuffer = stringToUTF8OnStack(path);
      //   var statBuf = _malloc(112);
      //   var err = __wasmfs_stat(pathBuffer, statBuf);
      //   const resultView = new Uint8Array(Module.HEAP8.buffer, statBuf, 112);
      //   const finalResult = new Uint8Array(resultView);
      //   _free(statBuf);
      //   console.log(finalResult);
        
      //   return err;
      // });

      return withStackSave(() => {

        var pathBuffer = stringToUTF8OnStack(path);

        var statBuf = _malloc({{{C_STRUCTS.stat.__size__}}});
        var err = __wasmfs_stat(pathBuffer, statBuf);
        console.log("stat error: ", err);
        // FS.handleError(-__wasmfs_stat(pathBuffer, statBuf));
        const resultView = new Uint8Array(Module.HEAP8.buffer, statBuf, {{{C_STRUCTS.stat.__size__}}});
        const resultCopy = new Uint8Array(resultView);
        const view = new DataView(resultCopy.buffer, 0);
        
        _free(statBuf);
        // console.log("ChatGPT Stuff: ", finalResult.subarray(12, 16));
        // console.log("SO Stuff: dev: ", view.getUint32(0, true));
        // console.log("SO Stuff: stmode: ", view.getUint32(12, true));
        // console.log("SO Stuff: nlink: ", view.getUint32(16, true));
        // console.log("SO Stuff: uid: ", view.getUint32(20, true));
        // console.log("SO Stuff: gid: ", view.getUint32(24, true));
        // console.log("SO Stuff: rdev: ", view.getUint32(28, true));
        // console.log("SO Stuff: size: ", view.getBigUint64(40, true));
        // console.log("SO Stuff: blksize: ", view.getUint32(48, true));
        // console.log("SO Stuff: blocks: ", view.getUint32(52, true));
        // console.log("SO Stuff: atime: ", view.getBigInt64(56, true));
        // console.log("SO Stuff: mtime: ", view.getBigInt64(72, true));
        // console.log("SO Stuff: ctime: ", view.getBigInt64(88, true));
        // console.log("SO Stuff: ino: ", view.getBigUint64(104, true));

        console.log("Super magic: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_dev, "u32")}}});
        console.log("Super magic 2: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_mode, "u32")}}})
        console.log("Super magic 3: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_nlink, "u32")}}})
        console.log("Super magic 4: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_uid, "u32")}}})
        console.log("Super magic 5: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_gid, "u32")}}})
        console.log("Super magic 6: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_rdev, "u32")}}})
        console.log("Super magic 7: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_size, "i64")}}})
        console.log("Super magic 8: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_blksize, "u32")}}})
        console.log("Super magic 9: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_blocks, "u32")}}})
        console.log("Super magic 10: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_atime, "i64")}}})
        console.log("Super magic 11: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_mtime, "i64")}}})
        console.log("Super magic 12: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_ctime, "i64")}}})
        console.log("Super magic 13: " + {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_ino, "u64")}}})


        var statsObj = {
          dev: view.getUint32(0, true),
          mode: view.getUint32(12, true),
          nlink: view.getUint32(16, true),
          uid: view.getUint32(20, true),
          gid: view.getUint32(24, true),
          rdev: view.getUint32(28, true),
          size: view.getBigInt64(40, true),
          blksize: view.getUint32(48, true),
          blocks: view.getUint32(52, true),
          atime: view.getBigInt64(56, true),
          mtime: view.getBigInt64(72, true),
          ctime: view.getBigInt64(88, true),
          ino: view.getBigUint64(104, true)
        }

        var statsObj = {
          dev: {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_dev, "u32")}}},
          mode: {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_mode, "u32")}}},
          nlink: {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_nlink, "u32")}}},
          uid: {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_uid, "u32")}}},
          gid: {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_gid, "u32")}}},
          rdev: {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_rdev, "u32")}}},
          size: view.getBigInt64(40, true),
          blksize: {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_blksize, "u32")}}},
          blocks: {{{ makeGetValue('statBuf', C_STRUCTS.stat.st_blocks, "u32")}}},
          atime: view.getBigInt64(56, true),
          mtime: view.getBigInt64(72, true),
          ctime: view.getBigInt64(88, true),
          ino: view.getBigUint64(104, true)
        }
        // console.log("statsObj: ", statsObj);

        return statsObj;
      })
    },
    // TODO: lstat
    lstat: (path) => {
      return withStackSave(() => {
        var pathBuffer = stringToUTF8OnStack(path);
        
        var statBuf = _malloc(112);
        var err = __wasmfs_lstat(pathBuffer, statBuf);
        // FS.handleError(-__wasmfs_lstat(pathBuffer, statBuf));
        console.log("lstat error: ", err);
        const resultView = new Uint8Array(Module.HEAP8.buffer, statBuf, 112);
        const resultCopy = new Uint8Array(resultView);
        const view = new DataView(resultCopy.buffer, 0);

        _free(statBuf);

        var statsObj = {
          dev: view.getUint32(0, true),
          mode: view.getUint32(12, true),
          nlink: view.getUint32(16, true),
          uid: view.getUint32(20, true),
          gid: view.getUint32(24, true),
          rdev: view.getUint32(28, true),
          size: view.getBigUint64(40, true),
          blksize: view.getUint32(48, true),
          blocks: view.getUint32(52, true),
          atime: view.getBigInt64(56, true),
          mtime: view.getBigInt64(72, true),
          ctime: view.getBigInt64(88, true),
          ino: view.getBigUint64(104, true)
        }
        // console.log("l-statsObj: ", statsObj);

        return statsObj;
      })
    },
    chmod: (path, mode) => {
      return withStackSave(() => {
        var buffer = stringToUTF8OnStack(path);
        return __wasmfs_chmod(buffer, mode);
      });
    },
    // TODO: lchmod
    // TODO: fchmod
    // TDOO: chown
    // TODO: lchown
    // TODO: fchown
    // TODO: truncate
    // TODO: ftruncate
    // TODO: utime
    findObject: (path) => {
      var result = __wasmfs_identify(path);
      if (result == {{{ cDefs.ENOENT }}}) {
        return null;
      }
      return {
        isFolder: result == {{{ cDefs.EISDIR }}},
        isDevice: false, // TODO: wasmfs support for devices
      };
    },
    readdir: (path) => {
      return withStackSave(() => {
        var pathBuffer = stringToUTF8OnStack(path);
        var entries = [];
        var state = __wasmfs_readdir_start(pathBuffer);
        if (!state) {
          // TODO: The old FS threw an ErrnoError here.
          throw new Error("No such directory");
        }
        var entry;
        while (entry = __wasmfs_readdir_get(state)) {
          entries.push(UTF8ToString(entry));
        }
        __wasmfs_readdir_finish(state);
        return entries;
      });
    }
    // TODO: mount
    // TODO: unmount
    // TODO: lookup
    // TODO: mknod
    // TODO: mkdev
    // TODO: rename
    // TODO: syncfs
    // TODO: llseek
    // TODO: ioctl

#endif
  },
  _wasmfs_get_num_preloaded_files__deps: ['$wasmFSPreloadedFiles'],
  _wasmfs_get_num_preloaded_files: function() {
    return wasmFSPreloadedFiles.length;
  },
  _wasmfs_get_num_preloaded_dirs__deps: ['$wasmFSPreloadedDirs'],
  _wasmfs_get_num_preloaded_dirs: function() {
    return wasmFSPreloadedDirs.length;
  },
  _wasmfs_get_preloaded_file_mode: function(index) {
    return wasmFSPreloadedFiles[index].mode;
  },
  _wasmfs_get_preloaded_parent_path__sig: 'vip',
  _wasmfs_get_preloaded_parent_path: function(index, parentPathBuffer) {
    var s = wasmFSPreloadedDirs[index].parentPath;
    var len = lengthBytesUTF8(s) + 1;
    stringToUTF8(s, parentPathBuffer, len);
  },
  _wasmfs_get_preloaded_child_path__sig: 'vip',
  _wasmfs_get_preloaded_child_path: function(index, childNameBuffer) {
    var s = wasmFSPreloadedDirs[index].childName;
    var len = lengthBytesUTF8(s) + 1;
    stringToUTF8(s, childNameBuffer, len);
  },
  _wasmfs_get_preloaded_path_name__sig: 'vip',
  _wasmfs_get_preloaded_path_name__deps: ['$lengthBytesUTF8', '$stringToUTF8'],
  _wasmfs_get_preloaded_path_name: function(index, fileNameBuffer) {
    var s = wasmFSPreloadedFiles[index].pathName;
    var len = lengthBytesUTF8(s) + 1;
    stringToUTF8(s, fileNameBuffer, len);
  },
  _wasmfs_get_preloaded_file_size__sig: 'pi',
  _wasmfs_get_preloaded_file_size: function(index) {
    return wasmFSPreloadedFiles[index].fileData.length;
  },
  _wasmfs_copy_preloaded_file_data__sig: 'vip',
  _wasmfs_copy_preloaded_file_data: function(index, buffer) {
    HEAPU8.set(wasmFSPreloadedFiles[index].fileData, buffer);
  }
});

DEFAULT_LIBRARY_FUNCS_TO_INCLUDE.push('$FS');
