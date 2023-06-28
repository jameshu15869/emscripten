// Copyright 2022 The Emscripten Authors.  All rights reserved.
// Emscripten is available under two separate licenses, the MIT license and the
// University of Illinois/NCSA Open Source License.  Both these licenses can be
// found in the LICENSE file.

#include <dirent.h>
#include <syscall_arch.h>
#include <unistd.h>

#include "backend.h"
#include "file.h"
#include "paths.h"

// Some APIs return data using a thread-local allocation that is never freed.
// This is simpler and more efficient as it avoids the JS caller needing to free
// the allocation (which would have both the overhead of free, and also of a
// call back into wasm), but on the other hand it does mean more memory may be
// used. This seems a reasonable tradeoff as heavy workloads should ideally
// avoid the JS API anyhow.

using namespace wasmfs;

extern "C" {

__wasi_fd_t wasmfs_create_file(char* pathname, mode_t mode, backend_t backend);
int wasmfs_create_directory(char* path, int mode, backend_t backend);
backend_t wasmfs_create_node_backend(const char* root __attribute__((nonnull)));
backend_t wasmfs_create_memory_backend(void);

// Copy the file specified by the pathname into JS.
// Return a pointer to the JS buffer in HEAPU8.
// The buffer will also contain the file length.
void* _wasmfs_read_file(char* path) {
  static_assert(sizeof(off_t) == 8, "File offset type must be 64-bit");

  struct stat file;
  int err = 0;
  err = stat(path, &file);
  if (err < 0) {
    emscripten_console_error("Fatal error in FS.readFile");
    abort();
  }

  // The function will return a pointer to a buffer with the file length in the
  // first 8 bytes. The remaining bytes will contain the buffer contents. This
  // allows the caller to use HEAPU8.subarray(buf + 8, buf + 8 + length).
  off_t size = file.st_size;

  static thread_local void* buffer = nullptr;
  buffer = realloc(buffer, size + sizeof(size));

  auto* result = (uint8_t*)buffer;
  *(off_t*)result = size;

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    emscripten_console_error("Fatal error in FS.readFile");
    abort();
  }
  [[maybe_unused]] int numRead = pread(fd, result + sizeof(size), size, 0);
  // TODO: Generalize this so that it is thread-proof.
  // Must guarantee that the file size has not changed by the time it is read.
  assert(numRead == size);
  err = close(fd);
  if (err < 0) {
    emscripten_console_error("Fatal error in FS.readFile");
    abort();
  }

  return result;
}

// Writes to a file, possibly creating it, and returns the number of bytes
// written successfully. If the file already exists, appends to it.
int _wasmfs_write_file(char* pathname, char* data, size_t data_size) {
  auto parsedParent = path::parseParent(pathname);
  if (parsedParent.getError()) {
    return 0;
  }
  auto& [parent, childNameView] = parsedParent.getParentChild();
  std::string childName(childNameView);

  std::shared_ptr<File> child;
  {
    auto lockedParent = parent->locked();
    child = lockedParent.getChild(childName);
    if (!child) {
      // Lookup failed; try creating the file.
      child = lockedParent.insertDataFile(childName, 0777);
      if (!child) {
        // File creation failed; nothing else to do.
        return 0;
      }
    }
  }

  auto dataFile = child->dynCast<DataFile>();
  if (!dataFile) {
    // There is something here but it isn't a data file.
    return 0;
  }

  auto lockedFile = dataFile->locked();
  int err = lockedFile.open(O_WRONLY);
  if (err < 0) {
    emscripten_console_error("Fatal error in FS.writeFile");
    abort();
  }

  auto offset = lockedFile.getSize();
  auto result = lockedFile.write((uint8_t*)data, data_size, offset);
  if (result != __WASI_ERRNO_SUCCESS) {
    return 0;
  }

  err = lockedFile.close();
  if (err < 0) {
    emscripten_console_error("Fatal error in FS.writeFile");
    abort();
  }

  return data_size;
}

int _wasmfs_mkdir(char* path, int mode) {
  return __syscall_mkdirat(AT_FDCWD, (intptr_t)path, mode);
}

int _wasmfs_rmdir(char* path){ return __syscall_unlinkat(AT_FDCWD, (intptr_t)path, AT_REMOVEDIR); }

int _wasmfs_open(char* path, int flags, mode_t mode) {
  printf("Made it to wasmfs_open: %d\n", flags);
  int err = __syscall_openat(AT_FDCWD, (intptr_t)path, flags, mode);
  printf("Open Cpp Err: %d\n", err);
  return err;
}

int _wasmfs_allocate(int fd, off_t offset, off_t len) {
  return __syscall_fallocate(fd, 0, offset, len);
}

int _wasmfs_mknod(char* path, mode_t mode, dev_t dev) {
  return __syscall_mknodat(AT_FDCWD, (intptr_t)path, mode, dev);
}

int _wasmfs_unlink(char* path) {
  return __syscall_unlinkat(AT_FDCWD, (intptr_t)path, 0);
}

int _wasmfs_chdir(char* path) { return __syscall_chdir((intptr_t)path); }

int _wasmfs_symlink(char* old_path, char* new_path) {
  return __syscall_symlink((intptr_t)old_path, (intptr_t)new_path);
}

intptr_t _wasmfs_readlink(char* path) {
  static thread_local void* readBuf = nullptr;
  readBuf = realloc(readBuf, PATH_MAX);
  int err = __syscall_readlinkat(AT_FDCWD, (intptr_t)path, (intptr_t)readBuf, PATH_MAX);
  if (err < 0) {
    return err;
  }
  return (intptr_t)readBuf;
}

int _wasmfs_write(int fd, void *buf, size_t count) {
  __wasi_ciovec_t iovs[1];
  iovs[0].buf = (uint8_t*)buf;
  iovs[0].buf_len = count;

  __wasi_size_t numBytes;
  __wasi_errno_t err = __wasi_fd_write(fd, iovs, 1, &numBytes);
  if (err) {
    return -err;
  }
  return numBytes;
}

int _wasmfs_pwrite(int fd, void *buf, size_t count, off_t offset) {
  __wasi_ciovec_t iovs[1];
  iovs[0].buf = (uint8_t*)buf;
  iovs[0].buf_len = count;

  __wasi_size_t numBytes;
  __wasi_errno_t err = __wasi_fd_pwrite(fd, iovs, 1, offset, &numBytes);
  if (err) {
    return -err;
  }
  return numBytes;
}

int _wasmfs_chmod(char* path, mode_t mode) {
  return __syscall_chmod((intptr_t)path, mode);
}

int _wasmfs_fchmod(int fd, mode_t mode) {
  return __syscall_fchmod(fd, mode);
}

int _wasmfs_lchmod(char* path, mode_t mode) {
  return __syscall_fchmodat(AT_FDCWD, (intptr_t)path, mode, AT_SYMLINK_NOFOLLOW);
}

int _wasmfs_llseek(int fd, off_t offset, int whence) {
  __wasi_filesize_t newOffset;
  int err = __wasi_fd_seek(fd, offset, whence, &newOffset);
  if (err > 0) {
    return -err;
  }
  return newOffset;
}

int _wasmfs_rename(char* oldpath, char* newpath) {
  return __syscall_renameat(AT_FDCWD, (intptr_t)oldpath, AT_FDCWD, (intptr_t)newpath);
};

int _wasmfs_read(int fd, void *buf, size_t count) {
  __wasi_iovec_t iovs[1];
  iovs[0].buf = (uint8_t *)buf;
  iovs[0].buf_len = count;

  __wasi_size_t numBytes;
  __wasi_errno_t err = __wasi_fd_read(fd, iovs, 1, &numBytes);
  if (err) {
    return -err;
  }
  return numBytes;
}

int _wasmfs_pread(int fd, void *buf, size_t count, off_t offset) {
  __wasi_iovec_t iovs[1];
  iovs[0].buf = (uint8_t *)buf;
  iovs[0].buf_len = count;

  __wasi_size_t numBytes;
  __wasi_errno_t err = __wasi_fd_pread(fd, iovs, 1, offset, &numBytes);
  if (err) {
    return -err;
  }
  return numBytes;
}

int _wasmfs_truncate(char* path, off_t length) {
  return __syscall_truncate64((intptr_t)path, length);
}

int _wasmfs_ftruncate(int fd, off_t length) {
  return __syscall_ftruncate64(fd, length);
}

int _wasmfs_close(int fd) {
  return __wasi_fd_close(fd);
}

int _wasmfs_utime(char *path, long atime_ms, long mtime_ms) {
  struct timespec times[2];
  times[0].tv_sec = atime_ms / 1000;
  times[0].tv_nsec = (atime_ms % 1000) * 1000000;
  times[1].tv_sec = mtime_ms / 1000;
  times[1].tv_nsec = (mtime_ms % 1000) * 1000000;

  return __syscall_utimensat(AT_FDCWD, (intptr_t)path, (intptr_t)times, 0);
};

int _wasmfs_stat(char* path, struct stat* statBuf) {
  return __syscall_stat64((intptr_t)path, (intptr_t)statBuf);
}

int _wasmfs_lstat(char* path, struct stat* statBuf) {
  return __syscall_lstat64((intptr_t)path, (intptr_t)statBuf);
}

int _wasmfs_mount(char* path, int backend_type) {
  backend_t created_backend;
  switch(backend_type) {
    case 0:
      created_backend = wasmfs_create_memory_backend();
      break;
    case 1:
      printf("Making node backend\n");
      created_backend = wasmfs_create_node_backend(path);
      break;
    default:
      return -EINVAL;
  }
  printf("Addr: %p\n", &created_backend);
  int err = wasmfs_create_directory(path, 0777, created_backend);
  printf("Err: %d\n", err);

  return err;
}

// Helper method that identifies what a path is:
//   ENOENT - if nothing exists there
//   EISDIR - if it is a directory
//   EEXIST - if it is a normal file
int _wasmfs_identify(char* path) {
  struct stat file;
  int err = 0;
  err = stat(path, &file);
  if (err < 0) {
    return ENOENT;
  }
  if (S_ISDIR(file.st_mode)) {
    return EISDIR;
  }
  return EEXIST;
}

struct wasmfs_readdir_state {
  int i;
  int nentries;
  struct dirent** entries;
};

struct wasmfs_readdir_state* _wasmfs_readdir_start(char* path) {
  struct dirent** entries;
  int nentries = scandir(path, &entries, NULL, alphasort);
  if (nentries == -1) {
    return NULL;
  }
  struct wasmfs_readdir_state* state =
    (struct wasmfs_readdir_state*)malloc(sizeof(*state));
  if (state == NULL) {
    return NULL;
  }
  state->i = 0;
  state->nentries = nentries;
  state->entries = entries;
  return state;
}

const char* _wasmfs_readdir_get(struct wasmfs_readdir_state* state) {
  if (state->i < state->nentries) {
    return state->entries[state->i++]->d_name;
  }
  return NULL;
}

void _wasmfs_readdir_finish(struct wasmfs_readdir_state* state) {
  for (int i = 0; i < state->nentries; i++) {
    free(state->entries[i]);
  }
  free(state->entries);
  free(state);
}

char* _wasmfs_get_cwd(void) {
  // TODO: PATH_MAX is 4K atm, so it might be good to reduce this somehow.
  static thread_local void* path = nullptr;
  path = realloc(path, PATH_MAX);
  return getcwd((char*)path, PATH_MAX);
}

} // extern "C"
