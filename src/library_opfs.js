/**
 * @license
 * Copyright 2013 The Emscripten Authors
 * SPDX-License-Identifier: MIT
 */

mergeInto(LibraryManager.library, {
  $OPFS__deps: ['wasmfs_create_opfs_backend'],
  $OPFS: {
    createBackend(opts) {
      return _wasmfs_create_opfs_backend()
    }
  },
});