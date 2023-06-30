#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/statfs.h>
#include <linux/magic.h>
#include <linux/limits.h> /* PATH_MAX */

#include <dirent.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>

#include "../base.h"
#include "../ltx.h"
#include "../msgpack/msgpack.h"


void mdev(int mjr, int mnr)
{
	const char *const path = "/dev/vport1p1";
	const int mnret = mknod(path, S_IFCHR, makedev(mjr, mnr));
	if (mnret)
		dprintf(STDERR_FILENO, "mknod('%s') -> %s", path, strerror(errno));
}

void enum_dir(const char *const path, int seen_vport1p1)
{
	DIR *dir = opendir(path);
	struct dirent *ent;

	if (!dir) {
		dprintf(STDERR_FILENO, "opendir('%s') -> %s\n",
			path, strerror(errno));
		return;
	}

	dprintf(STDERR_FILENO, "> ls %s\n", path);
	while ((ent = readdir(dir))) {
		if (ent->d_name[0] == '.')
			continue;

		char subpath[PATH_MAX];
		sprintf(subpath, "%s/%s", path, ent->d_name);

		if (strcmp(ent->d_name, "dev")) {
			dprintf(STDERR_FILENO, "%s\n", ent->d_name);

			if (!strcmp(ent->d_name, "vport1p1"))
				seen_vport1p1 = 1;
		} else {
			char devbuf[8] = { 0 };
			int mjr, mnr;
			const int devfd = open(subpath, O_RDONLY);

			if (devfd < 0)
				dprintf(STDERR_FILENO, "open('%s') -> %s", subpath, strerror(errno));

			const int rret = read(devfd, devbuf, 7);
			if (rret < 0)
				dprintf(STDERR_FILENO, "read('%s') -> %s", subpath, strerror(errno));

			close(devfd);

			sscanf(devbuf, "%d:%d", &mjr, &mnr);
			dprintf(STDERR_FILENO, "dev -> %s    -> %d:%d\n", devbuf, mjr, mnr);

			if (seen_vport1p1)
				mdev(mjr, mnr);
		}

		if (ent->d_type != DT_DIR)
			continue;

		enum_dir(subpath, seen_vport1p1);
	}

	closedir(dir);
}

void init(void)
{
	dprintf(STDERR_FILENO, "> LTX is running as init!\n");

	const int mksysret = mkdir("/sys", 0666);
	if (mksysret)
		dprintf(STDERR_FILENO, "mkdir('/sys') -> %s", strerror(errno));
	const int mret = mount("none", "/sys", "sysfs", 0, NULL);
	if (mret)
		dprintf(STDERR_FILENO, "mount('/sys') -> %s", strerror(errno));

	enum_dir("/sys/devices", 0);
	enum_dir("/dev", 0);

	const int sfd = open("/dev/vport1p1", O_RDWR | O_CLOEXEC);
	if (sfd < 0)
		dprintf(STDERR_FILENO, "open('/dev/vport1p1') -> %s", strerror(errno));

	dup2(sfd, STDIN_FILENO);
	dup2(sfd, STDOUT_FILENO);
}

int main(void)
{
	struct ltx_session *session;

	if (getpid() == 1)
		init();

	session = ltx_session_init(STDIN_FILENO, STDOUT_FILENO);
	ltx_start_event_loop(session);
	ltx_session_destroy(session);

	return 0;
}
