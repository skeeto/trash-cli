# trash-cli: FreeDesktop trash can CLI implemented in C

A feature-complete rewrite of [the original trash-cli][py] in a language
more suited to systems programming. Its purpose is to surpass the original
in every aspect. The project includes a comprehensive test suite that runs
against a virtual file system.

[py]: https://github.com/andreafrancia/trash-cli

## Install

Requires `cc` and `make`. By default installs to `~/.local`:

    $ make install

Or a system-wide installation:

    $ sudo make install PREFIX=/usr

## Uninstall

    $ make uninstall

If the install was system-wide:

    $ sudo make uninstall PREFIX=/usr

## Testing

The tests do create no files and does not touch the file system.

    $ make check

## Upstream bugs fixed/avoided

1. **`trash-restore --sort none` works**: it keeps the scan order and exits 0
   (upstream always raised `TypeError` because the `NoSorter` *class* was
   returned where an instance was expected).
2. **`XDG_DATA_HOME`**: an empty value is treated like an unset one, so the
   `$HOME/.local/share/Trash` fallback applies (upstream used presence-only
   checking, making the home trash literally `/Trash`).
3. **Undated restore entries sort last** (printing `None`) instead of raising
   `TypeError` when sorted among real dates.
4. **`trash-restore`'s zero-candidates message names the searched path**:
   `No files trashed from current dir ('<realpath of cwd>')` without a `path`
   argument, else `No files trashed from '<path>'` (upstream always claimed
   "current dir").
5. **`trash-restore` honors `TRASH_VOLUMES`** like list/empty/rm (upstream
   ignored it).
6. **`trash-rm ''`** (empty pattern) matches nothing and exits 0 (upstream
   crashed with `IndexError` on a non-empty trash).
7. **Non-UTF-8 or otherwise unparsable trashinfo files are warned about and
   skipped, exit 0**, in `trash-list` and `trash-rm` (upstream crashed with
   `UnicodeDecodeError`, exit 1); `trash-restore` and `trash-empty` behaved
   leniently already and do the same.
8. **`trash-empty`'s `days` overflow is a clean usage error**: a value whose
   cutoff would leave the representable date range (years 1..9999), e.g.
   `99999999999999999999`, gives
   `trash-empty: error: argument days: value out of range: '<value>'`, exit 2
   (upstream died on an uncaught `OverflowError`, exit 1).
9. **`trash-put -i`/`trash-empty -i` on EOF** print
   `<prog>: EOF while reading the answer` on stderr and exit 1 (upstream:
   unhandled `EOFError` traceback).
10. **`trash-empty -i` with zero trash dirs** prints
    `No trash directories to empty.` with a newline and exits 0 without
    waiting for input (upstream used the text as an `input()` prompt).
11. **`trash-list --all-users` skips trash dirs of other users that cannot be
    read** and exits 0 (upstream died on `PermissionError`).
12. **Trashing a read-only directory works**: when `rename(2)` fails with
    `EACCES` because moving a directory to a different parent rewrites its
    `..` entry (which needs write access to the directory itself on Linux),
    `trash-put` grants owner-write for the move and restores the original
    mode on the backup copy (spec 5.6: only removing from the parent must be
    allowed).
