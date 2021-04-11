/**
 * www - serve a file over HTTP
 *
 * SYNOPSIS
 *   www [FILE=index.html] [[HOST=localhost][: PORT=8080]] [SHELL-COMMAND | -- COMMAND [ARG]...]
 *
 * DESCRIPTION
 *   Serve a file or the output of a command over HTTP.
 *
 * EXAMPLE
 *
 *   Serve a file:
 *
 *       $ www /etc/passwd :8000
 *       # On the other side:
 *       $ curl -OJ https://localhost:8000
 *
 *   Serve multiple files:
 *
 *       $ www a.tar 127.0.0.1 -- tar -cf - *.mkv
 *       # On the other side:
 *       $ curl https://127.0.0.1:8080 | tar -xf -
 *
 *   Serve a command:
 *
 *       $ www a.out : -- date +%s
 *
 *   Serve a shell command:
 *
 *       $ www : : 'yes | sed ='
 *
 *       $ www : : 'echo $0: Hello $1.'
 *       # On the other side:
 *       $ curl "https://localhost:8080/$USER"
 *       www-cmd: Hello user
 *
 * COPYRIGHT
 *   Public domain.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RFC_2822 "%a, %d %b %Y %T %z"

enum LogLevel {
	DEBUG,
	ERROR,
	FATAL,
};

atomic_size_t nb_clients;

static char const *path;
static char const *filename;
static char **command;
static int fd;

static void
www_log(enum LogLevel level, char const *format, ...)
{
	va_list ap;
	va_start(ap, format);
	char buf[512];
	vsnprintf(buf, sizeof buf, format, ap);
	va_end(ap);

	char date[50];
	time_t now;
	time(&now);
	strftime(date, sizeof date, RFC_2822, localtime(&now));

	switch (level) {
	case DEBUG:
		fprintf(stderr, "[%s] %s\n", date, buf);
		break;

	case ERROR:
	case FATAL:
		fprintf(stderr, "\e[31m[%s] \e[1m%s\e[m\n", date, buf);
		if (FATAL == level)
			exit(EXIT_FAILURE);
		break;
	}
}

static char *
straddr(struct sockaddr const *sa)
{
	char addr_buf[INET6_ADDRSTRLEN];

	static char buf[10 + 2 + 1 + sizeof addr_buf + 1 + 1 + sizeof "65536"];

	void *addr = NULL;
	in_port_t port = 0;

	switch (sa ? sa->sa_family : AF_UNSPEC) {
	case AF_INET:
		addr = &((struct sockaddr_in *)sa)->sin_addr;
		port = ((struct sockaddr_in *)sa)->sin_port;
		break;

	case AF_INET6:
		addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
		port = ((struct sockaddr_in6 *)sa)->sin6_port;
		break;

	default:
		return "(unknown)";
	}

	sprintf(buf, "%s%s%s:%"PRId32,
			AF_INET != sa->sa_family ? "[" : "",
			inet_ntop(sa->sa_family, addr, addr_buf, sizeof addr_buf),
			AF_INET != sa->sa_family ? "]" : "",
			ntohs(port));

	return buf;
}

static void
serve_file(char *headers, int cfd)
{
	struct stat st;
	if (fstat(fd, &st) < 0) {
		www_log(ERROR, "Failed to stat file: %s", strerror(errno));
		return;
	}

	loff_t offset = 0, end_offset = LONG_MAX;

	char const *p;
	p = strstr(headers, "Range:");
	if (p)
		sscanf(p + 6, " bytes=%ld-%ld", &offset, &end_offset);

	if (st.st_size < end_offset)
		end_offset = st.st_size;

	char last_modified[50], date[50];
	time_t now;
	time(&now);
	strftime(date, sizeof date, RFC_2822, localtime(&now));
	strftime(last_modified, sizeof last_modified, RFC_2822, localtime(&st.st_mtime));

	int size = sprintf(headers,
			"HTTP/1.1 200 OK\r\n"
			"Date: %s\r\n"
			"Last-Modified: %s\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Content-Disposition: attachment; filename=\"%s\"\r\n"
			"Content-Length: %lu\r\n"
			"Accept-Ranges: bytes\r\n"
			"Content-Range: bytes %ld-%ld/%lu\r\n"
			"Connection: close\r\n"
			"\r\n",
			date,
			last_modified,
			filename,
			end_offset - offset,
			offset, end_offset, st.st_size);
	if (write(cfd, headers, size) < 0)
		return;

	if (sendfile(cfd, fd, &offset, end_offset - offset) < 0) {
		www_log(ERROR, "Failed to send file: %s", strerror(errno));
		return;
	}
}

static void
serve_cmd(char *headers, int cfd)
{
	int size;
	char head[1 << 10];

	size = sprintf(head,
			"HTTP/1.1 200 OK\r\n"
			"Cache-Control: no-cache\r\n"
			"Transfer-Encoding: chunked\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Content-Disposition: attachment; filename=\"%s\"\r\n"
			"Connection: close\r\n"
			"\r\n",
			filename);
	if (write(cfd, head, size) < 0)
		return;

	int pair[2];
	if (pipe2(pair, O_CLOEXEC) < 0) {
		www_log(ERROR, "Failed to open pipe: %s", strerror(errno));
		return;
	}

	int verb_start, verb_end;
	int path_start, path_end;
	sscanf(headers, "%n%*[^ ]%n %n%*[^ ]%n HTTP",
			&verb_start, &verb_end,
			&path_start, &path_end);
	if (path_end < 0) {
		www_log(ERROR, "Malformed request");
		return;
	}
	char const *path = headers + path_start + 1;
	headers[path_end] = '\0';

	www_log(DEBUG, "Request '%s'", path);

	pid_t pid;
	if (!(pid = vfork())) {
		close(STDIN_FILENO);
		dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);

		dup2(pair[1], STDOUT_FILENO);

		if (!strcmp(command[0], "--"))
			execvp(command[1], command + 1);
		else
			execlp("sh", "sh", "-euc", command[0],
					/* arg0= */ "www-cmd",
					/* arg1= */ path,
					NULL);
		www_log(FATAL, "Failed to spawn process: %s", strerror(errno));
	} else if (0 < pid) {
		enum { BUF_SIZE = 1 << 18 };

		close(pair[1]);

		char buf[20 + BUF_SIZE + 2];
		buf[18] = '\r';
		buf[19] = '\n';

		while (0 <= (size = read(pair[0], buf + 20, BUF_SIZE))) {
			char *start = buf + 18, *end = buf + 20 + size;
			unsigned n = size;
			do
				*--start = "0123456789ABCDEF"[n % 16];
			while ((n /= 16));

			*end++ = '\r';
			*end++ = '\n';

			if (write(cfd, start, end - start) < 0) {
				www_log(ERROR, "Failed to write: %s", strerror(errno));
				break;
			}

			if (!size)
				break;
		}

		close(pair[0]);
	}
}

static int
parse_request(int cfd, char *headers, size_t headers_size)
{
	int size = read(cfd, headers, headers_size - 1);
	if (size < 0) {
		www_log(ERROR, "Failed to read headers: %s", strerror(errno));
		return -1;
	}
	headers[size] = '\0';

	return 0;
}

static void *
worker(void *arg)
{
	atomic_fetch_add_explicit(&nb_clients, 1, memory_order_relaxed);

	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} csa;

	int cfd = (int)(uintptr_t)arg;

	struct sockaddr *csa_sa = 0 <= getpeername(cfd, &csa.sa, &(socklen_t){ sizeof csa }) ? &csa.sa : NULL;

	www_log(DEBUG, "Hello %s", straddr(csa_sa));

	char headers[4096];
	if (0 <= parse_request(cfd, headers, sizeof headers)) {
		if (!command)
			serve_file(headers, cfd);
		else
			serve_cmd(headers, cfd);
	}

	www_log(DEBUG, "Bye %s", straddr(csa_sa));

	shutdown(cfd, SHUT_RDWR);
	close(cfd);

	if (1 == atomic_fetch_sub_explicit(&nb_clients, 1, memory_order_relaxed))
		www_log(DEBUG, "All clients gone");

	return NULL;
}

int
main(int argc, char *argv[])
{
	static struct sigaction const SA_IGNORE = {
		.sa_handler = SIG_IGN,
		.sa_flags = SA_RESTART,
	};

	sigaction(SIGCHLD, &SA_IGNORE, NULL);
	sigaction(SIGHUP, &SA_IGNORE, NULL);
	sigaction(SIGPIPE, &SA_IGNORE, NULL);
	sigaction(SIGWINCH, &SA_IGNORE, NULL);

	path = 1 < argc ? argv[1] : "index.html";
	if ((filename = strrchr(path, '/')))
		++filename;
	else
		filename = path;

	if (argc <= 3 && (fd = open(path, O_CLOEXEC | O_RDONLY)) < 0)
		www_log(FATAL, "Failed to open %s: %s", path, strerror(errno));

	char const *node = "localhost";
	char const *service = "8080";

	if (2 < argc) {
		char const *p = argv[2];
		if (':' == *p) {
			if (p[1])
				service = p + 1;
		} else if ('[' == *p) {
			node = p + 1;
			p = strchr(node, ']');
			if (p) {
				*(char *)p = '\0';
				if (':' == p[1] && p[2])
					service = p + 2;
			}
		} else {
			node = p;
			p = strchr(node, ':');
			if (p) {
				*(char *)p = '\0';
				if (p[1])
					service = p + 1;
			}
		}
	}

	struct addrinfo *info, hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_CANONNAME,
	};

	for (int res; (res = getaddrinfo(node, service, &hints, &info));)
		www_log(FATAL, "Failed to resolve address: %s",
				EAI_SYSTEM == res
					? strerror(errno)
					: gai_strerror(res));

	int sfd = -1;

	for (struct addrinfo *ai = info; ai; ai = ai->ai_next) {
		sfd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
		if (sfd < 0)
			continue;

		static int const YES = 1;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &YES, sizeof YES) < 0)
			www_log(ERROR, "Failed to set socket options");

		if (bind(sfd, ai->ai_addr, ai->ai_addrlen) < 0) {
			www_log(ERROR, "Failed to bind to %s", straddr(ai->ai_addr));
			close(sfd);
			continue;
		}

		if (listen(sfd, 2) < 0) {
			www_log(FATAL, "Failed to listen on %s: %s", straddr(ai->ai_addr), strerror(errno));
			close(sfd);
			continue;
		}

		www_log(DEBUG, "Listening on http://%s%s%s%s",
				straddr(ai->ai_addr),
				ai->ai_canonname ? " (" : "",
				ai->ai_canonname ? ai->ai_canonname : "",
				ai->ai_canonname ? ")" : "");

		break;
	}

	freeaddrinfo(info);

	if (sfd < 0)
		www_log(FATAL, "Failed to open socket: %s", strerror(errno));

	if (3 < argc)
		command = &argv[3];

	for (int cfd; 0 <= (cfd = accept(sfd, NULL, NULL));) {
		pthread_t thread;
		pthread_create(&thread, NULL, worker, (void *)(uintptr_t)cfd);
	}

	return EXIT_FAILURE;
}
