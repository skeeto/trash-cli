CC      = cc
CFLAGS  = -O -Wall -Wextra -Wconversion
LDFLAGS = -s
LDLIBS  =
PREFIX  = $$HOME/.local

.PHONY: check clean install uninstall

bins = \
  bin/trash-empty \
  bin/trash-list \
  bin/trash-put \
  bin/trash-restore \
  bin/trash-rm

mans = \
  man/man1/trash.1 \
  man/man1/trash-empty.1 \
  man/man1/trash-list.1 \
  man/man1/trash-put.1 \
  man/man1/trash-restore.1 \
  man/man1/trash-rm.1

trash: trash.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ trash.c $(LDLIBS)

trash-test: trash.c
	$(CC) $(CFLAGS) -DTEST $(LDFLAGS) -o $@ trash.c $(LDLIBS)

check: trash-test
	./trash-test

clean:
	rm -f trash trash-test

install: trash $(mans)
	mkdir -p $(DESTDIR)$(PREFIX)/bin/
	cp trash $(DESTDIR)$(PREFIX)/bin/
	for b in $(bins); do ln -sf trash $(DESTDIR)$(PREFIX)/$$b; done
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1/
	cp $(mans) $(DESTDIR)$(PREFIX)/share/man/man1/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/trash
	for b in $(bins); do rm -f $(DESTDIR)$(PREFIX)/$$b; done
	for m in $(mans); do rm -f $(DESTDIR)$(PREFIX)/share/$$m; done
