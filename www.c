/* www - serving one file over HTTP
 *
 * USAGE:
 *   www      a.tar -- tar -cf - dir
 *   www 8888 file
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RFC_2822 "%a, %d %b %Y %T %z"

enum LogLevel {
	DEBUG,
	ERROR,
	FATAL,
};

static in_port_t port;
static char const *address;
static char const *path;
static char const *filename;
static char const *command;
static char **command_args;
static int fd;

static struct sigaction const sa_ignore = {
	.sa_handler = SIG_IGN,
	.sa_flags = SA_RESTART,
};

static void
www_log(enum LogLevel level, char const *format, ...)
{
	int res = errno;

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
		printf("[%s] %s\n", date, buf);
		break;

	case ERROR:
	case FATAL:
		fprintf(stderr, "\e[31m[%s] \e[1m%s: %s\e[m\n", date, buf, strerror(res));
		if (FATAL == level)
			exit(EXIT_FAILURE);
		break;
	}
}

static void
serve_file(char *headers, int client)
{
	struct stat st;
	if (fstat(fd, &st) < 0) {
		www_log(ERROR, "Failed to stat file");
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
	if (write(client, headers, size) < 0)
		return;

	if (sendfile(client, fd, &offset, end_offset - offset) < 0) {
		www_log(ERROR, "Failed to send file");
		return;
	}
}

static void
serve_cmd(char *headers, int client)
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
	if (write(client, head, size) < 0)
		return;

	int pair[2];
	if (pipe2(pair, O_CLOEXEC) < 0) {
		www_log(ERROR, "Failed to open pipe");
		return;
	}

	pid_t pid;
	if (!(pid = vfork())) {
		close(pair[0]);
		close(STDIN_FILENO);
		dup2(pair[1], STDOUT_FILENO);
		close(pair[1]);
		if (strcmp(command, "--"))
			execlp("sh", "sh", "-c", command);
		else
			execvp(command_args[0], command_args);
		www_log(FATAL, "Failed to spawn process");
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

			if (write(client, start, end - start) < 0) {
				www_log(ERROR, "Failed to write");
				break;
			}

			if (!size)
				break;
		}

		close(pair[0]);
	}
}

static int
parse_request(int client, char *headers, size_t headers_size)
{
	int size = read(client, headers, headers_size - 1);
	if (size < 0) {
		www_log(ERROR, "Failed to read headers");
		return -1;
	}
	headers[size] = '\0';

	return 0;
}

static void *
worker(void *arg)
{
	int client = (int)(uintptr_t)arg;

	char headers[4096];
	if (0 <= parse_request(client, headers, sizeof headers)) {
		if (!command)
			serve_file(headers, client);
		else
			serve_cmd(headers, client);
	}

	www_log(DEBUG, "Close %d", client);

	shutdown(client, SHUT_RDWR);
	close(client);

	return NULL;
}

int
main(int argc, char *argv[])
{
	if (0) {
	help:
		errno = -EINVAL;
		www_log(ERROR, "Failed to parse arguments");
		return EXIT_FAILURE;
	}

	char **arg = &argv[1];

	if (!*arg)
		goto help;
	int pos = 0;
	sscanf(*arg, "%*[^:]:%n%hu", &pos, &port);
	if (0 < pos) {
		address = *arg;
		(*arg)[pos - 1] = '\0';
		++arg;
	} else {
		sscanf(*arg, "%hu%n", &port, &pos);
		if (1 < pos && !(*arg)[pos])
			++arg;
		else
			port = 0;
	}

	if (!port)
		port = 8080;

	if (!*arg)
		goto help;
	path = *arg++;
	if ((filename = strrchr(path, '/')))
		++filename;
	else
		filename = path;

	command = *arg;
	command_args = arg + 1;

	if (!command && (fd = open(path, O_CLOEXEC | O_RDONLY)) < 0)
		www_log(FATAL, "Failed to open input file '%s'", path);

	int server;
	if ((server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
		www_log(FATAL, "Failed to open socket");

	static int const YES = 1;
	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &YES, sizeof YES))
		www_log(ERROR, "Failed to set socket options");

	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = !address ? INADDR_ANY : inet_addr(address),
		.sin_port = htons(port),
	};

	if (bind(server, (struct sockaddr *)&sin, sizeof sin) < 0)
		www_log(FATAL, "Failed to bind to %s:%d",
				inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

	if (listen(server, 2) < 0)
		www_log(FATAL, "Failed to listen on %s:%d",
				inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

	sigaction(SIGCHLD, &sa_ignore, NULL);
	sigaction(SIGHUP, &sa_ignore, NULL);
	sigaction(SIGPIPE, &sa_ignore, NULL);
	sigaction(SIGWINCH, &sa_ignore, NULL);

	www_log(DEBUG, "Listening on http://%s:%d",
			inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));

	for (int client;
	     0 <= (client = accept(server, (struct sockaddr *)&sin, (socklen_t[]){ sizeof sin }));)
	{
		www_log(DEBUG, "Accept %d: %s", client, inet_ntoa(sin.sin_addr));

		pthread_t thread;
		pthread_create(&thread, NULL, worker, (void *)(uintptr_t)client);
	}

	return EXIT_FAILURE;
}
