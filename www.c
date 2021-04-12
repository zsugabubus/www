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
 *       $ www : : 'echo $0: Hello $2.'
 *       # On the other side:
 *       $ curl "https://localhost:8080/$USER"
 *       www-cmd: Hello user
 *
 *   Serve directory as a playlist:
 *
 *       $ www ~/music : 'echo "#EXTM3U"; printf "%s\n" *.mp3'
 *
 * COPYRIGHT
 *   Public domain.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
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
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define RFC_2822 "%a, %d %b %Y %T %z"

#define NSEC_PER_SEC 1000000000

static char const HTTP_400_BAD_REQUEST[] = "400 Bad Request";
static char const HTTP_400_BAD_REQUEST_TOO_LONG[] = "400 Bad Request: Too long";
static char const HTTP_403_FORBIDDEN[] = "403 Forbidden";
static char const HTTP_404_NOT_FOUND[] = "404 Not Found";
static char const HTTP_405_METHOD_NOT_ALLOWED[] = "405 Method Not Allowed";
static char const HTTP_500_INTERNAL_SERVER_ERROR[] = "500 Internal Server Error";

enum LogLevel {
	DEBUG,
	ERROR,
	FATAL,
};

typedef struct {
	char *method;
	char *path;
	char *query;
	char *headers;
	char *body;
	size_t body_size;
	char buf[8196];
} HTTPRequest;

static char const *shell;
static atomic_size_t nb_clients;
static char const *filename;
static char **command;
static int main_fd = -1;

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

	default:
		abort();
	}
}

static int
www_writev(int cfd, struct iovec *iov, int nb_iov)
{
	for (;;) {
		ssize_t res = writev(cfd, iov, nb_iov);
		if (res < 0)
			return -errno;
		else if (!res)
			return -EBADF;

		size_t written = res;

		while (iov[0].iov_len <= written) {
			written -= (iov++)->iov_len;
			if (!--nb_iov)
				return 0;
		}

		iov[0].iov_base += written;
		iov[0].iov_len  -= written;
	}

	return 0;
}

static int
www_write(int cfd, char const *buf, size_t buf_size)
{
	struct iovec iov[1];

	iov[0].iov_base = (char *)buf;
	iov[0].iov_len = buf_size;

	return www_writev(cfd, iov, 1);
}

static int
www_write_chunked(int fd, char const *buf, size_t buf_size)
{
	struct iovec iov[3];
	char prefix[sizeof buf_size * 2 + 2];

	char *p = (&prefix)[1];
	size_t n = buf_size;

	*--p = '\n';
	*--p = '\r';

	iov[2].iov_base = p;
	iov[2].iov_len = 2;

	do
		*--p = "0123456789ABCDEF"[n % 16];
	while ((n /= 16));

	iov[0].iov_base = p;
	iov[0].iov_len = (&prefix)[1] - p;

	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = buf_size;

	return www_writev(fd, iov, 3);
}

static int
www_write_response(int cfd, char const *status)
{
	char buf[1 << 10];

	int buf_size = snprintf(buf, sizeof buf,
			"HTTP/1.1 %s\r\n"
			"Content-Type: text/html; charset=UTF-8\r\n"
			"\r\n"
			"<!DOCTYPE html>\n"
			"<html>\n"
			"<head></head>\n"
			"<body>\n"
			"\t<pre><h1 style=\"text-align: center\">%s</h1><hr></pre>\n"
			"</body>\n",
			status,
			status);
	if ((int)sizeof buf <= buf_size)
		abort();

	return www_write(cfd, buf, buf_size);
}

static char *
www_straddr(struct sockaddr const *sa)
{
	char addr_buf[INET6_ADDRSTRLEN];

	_Thread_local static char buf[10 + 2 + 1 + sizeof addr_buf + 1 + 1 + sizeof "65536"];

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

	sprintf(buf, "%s%s%s:%hu",
			AF_INET != sa->sa_family ? "[" : "",
			inet_ntop(sa->sa_family, addr, addr_buf, sizeof addr_buf),
			AF_INET != sa->sa_family ? "]" : "",
			ntohs(port));

	return buf;
}

static void
www_sanitize_uri(HTTPRequest *req)
{
	char *dest = req->path;
	for (char *src = dest; *src;)
		/* ^/ -> ^ */
		if ('/' == src[0] && dest == req->path)
			src += 1;
		/* /../ -> /. */
		else if ('/' == src[0] &&
		    '.' == src[1] &&
		    '.' == src[2] &&
		    ('/' == src[3] || !src[3]))
			src += 3;
		/* // -> / */
		else if ('/' == src[0] &&
			 '/' == src[1])
			src += 1;
		/* %XX -> Y */
		else if ('%' == src[0] &&
		         isxdigit(src[1]) &&
		         isxdigit(src[2]))
		{
			*dest++ =
				(('9' < src[1] ? (src[1] | ' ') - 'a' + 10 : src[1] - '0') << 4) |
				 ('9' < src[2] ? (src[2] | ' ') - 'a' + 10 : src[2] - '0');
			src += 3;
		/* x -> x */
		} else
			*dest++ = *src++;
	*dest = '\0';
}

static char const *
www_parse_request(int cfd, HTTPRequest *req)
{
	ssize_t size = read(cfd, req->buf, sizeof req->buf - 1);
	if (size < 0) {
		www_log(ERROR, "Failed to read headers: %s", strerror(errno));
		return HTTP_400_BAD_REQUEST;
	}
	size_t buf_size = size;
	req->buf[buf_size] = '\0';

	char const *buf_end = req->buf + buf_size;

	char *p = req->buf;

	if (!(p = memchr((req->method = p), ' ', buf_end - p))) {
	bad_request:
		www_log(ERROR, "Bad request");
		return HTTP_400_BAD_REQUEST;
	}
	*p++ = '\0';

	if (!(p = memchr((req->path = p), ' ', buf_end - p)))
		goto bad_request;
	*p++ = '\0';

	if (req->buf + buf_size < p + 10 || memcmp(p, "HTTP/1.1\r\n", 10))
		goto bad_request;
	p += 10;

	req->headers = p;
	for (;;) {
		char const *header = p;
		for (; ('a' <= *p && *p <= 'z') ||
		       ('A' <= *p && *p <= 'Z') ||
		       ('-' == *p); ++p)
			*p = ('-' == *p ? '_' : ~' ' & *p);

		if (':' != *p) {
			if (header == p && ('\r' == p[0] && '\n' == p[1])) {
				*p = '\0';
				p += 2;
				break;
			}
			return HTTP_400_BAD_REQUEST;
		}
		*p = '\0';

		p = memchr(p, '\r', buf_end - p);
		if (!p)
			/* FIXME: We expect request headers to be written at once. */
			return HTTP_400_BAD_REQUEST_TOO_LONG;
		else if ('\n' != p[1])
			return HTTP_400_BAD_REQUEST;
		*p = '\0';
		p += 2;
	}

	req->body = p;
	req->body_size = buf_end - p;

	if ((p = strchr(req->path, '?'))) {
		*p = '\0';
		req->query = p + 1;
	} else
		req->query = NULL;

	www_sanitize_uri(req);

	www_log(DEBUG, "Request %s '%s'%s%s",
			req->method, req->path,
			req->query ? "?" : "",
			req->query ? req->query : "");

	return NULL;
}

static char const *
www_get_header(HTTPRequest const *req, char const *s)
{
	size_t s_size = strlen(s);

	char const *p = req->headers;
	for (;;) {
		char const *header = p;
		if (!*header)
			return NULL;

		size_t header_size = strlen(header);

		char const *value = header + header_size + 1 /* : */;

		if (s_size == header_size &&
		    !memcmp(s, header, header_size))
		{
			while (' ' == *value)
				++value;
			return value;
		}

		p = value + strlen(value) + 2 /* \r\n */;
	}
}

static char const *
www_serve_cmd(int cfd, HTTPRequest *req)
{
	if (!command)
		return HTTP_500_INTERNAL_SERVER_ERROR;

	int size;
	char headers[1 << 10];

	size = snprintf(headers, sizeof headers,
			"HTTP/1.1 200 OK\r\n"
			"Cache-Control: no-cache\r\n"
			"Transfer-Encoding: chunked\r\n"
			"Content-Type: application/octet-stream\r\n"
			"Content-Disposition: attachment; filename=\"%s\"\r\n"
			"Connection: close\r\n"
			"\r\n",
			filename);
	if ((int)sizeof headers <= size)
		return HTTP_500_INTERNAL_SERVER_ERROR;
	if (www_write(cfd, headers, size) < 0)
		return HTTP_500_INTERNAL_SERVER_ERROR;

	int pair[2];
	if (pipe2(pair, O_CLOEXEC) < 0) {
		www_log(ERROR, "Failed to open pipe: %s", strerror(errno));
		return HTTP_500_INTERNAL_SERVER_ERROR;
	}

	pid_t pid;
	if (!(pid = vfork())) {
		close(STDIN_FILENO);
		dup2(!strcmp(req->method, "GET")
			? open("/dev/null", O_CLOEXEC | O_RDONLY)
			: cfd, STDIN_FILENO);

		dup2(pair[1], STDOUT_FILENO);

		fchdir(main_fd);
		for (char const *header = req->headers; *header;) {
			char const *value = header + strlen(header) + 1 /* : */;

			char name[128];
			snprintf(name, sizeof name, "HTTP_%s", header);

			while (' ' == *value)
				++value;

			setenv(name, value, 0);

			header = value + strlen(value) + 2 /* \r\n */;
		}

		if (!strcmp(command[0], "--")) {
			www_log(DEBUG, "Spawning %s", command[1]);
			execvp(command[1], command + 1);
		} else {
			www_log(DEBUG, "Spawning %s -c '%s'", shell, command[0]);
			execlp(shell, shell, "-euc", command[0],
					/* argv[0] = */ "www-cmd",
					/* argv[1] = */ req->method,
					/* argv[2] = */ req->path,
					/* argv[3] = */ req->query,
					NULL);
		}
		www_log(FATAL, "Failed to spawn process: %s", strerror(errno));
	} else if (0 < pid) {
		close(pair[1]);

		char buf[1 << 18];

		while (0 <= (size = read(pair[0], buf, sizeof buf)))
			if (www_write_chunked(cfd, buf, size) < 0 || !size)
				break;

		close(pair[0]);
	}

	return NULL;
}

static char const *
www_serve_file(int cfd, HTTPRequest *req)
{
	if (req->query)
		return www_serve_cmd(cfd, req);

	char const *ret = NULL;

	if (strcmp(req->method, "GET") &&
	    strcmp(req->method, "HEAD"))
	{
		ret = www_serve_cmd(cfd, req);
		if (ret)
			ret = HTTP_405_METHOD_NOT_ALLOWED;
		return ret;
	}

	int fd = main_fd;
	struct stat st;

	if (fstat(fd, &st) < 0) {
		ret = www_serve_cmd(cfd, req);
		if (ret) {
			www_log(ERROR, "Failed to stat file: %s", strerror(errno));
			return HTTP_500_INTERNAL_SERVER_ERROR;
		}
		return ret;
	}

	DIR *dir = NULL;
	int tmp_fd = -1;

	enum {
		A_PLAIN,
		A_HTML,
	} accept;

	char headers[1 << 10];
	char last_modified[50], date[50];

	time_t now;
	strftime(date, sizeof date, RFC_2822, localtime((time(&now), &now)));
	strftime(last_modified, sizeof last_modified, RFC_2822, localtime(&st.st_mtime));

	loff_t offset = 0, end_offset = LONG_MAX;

	int headers_size;
	if (S_ISDIR(st.st_mode)) {
		/* Serve command instead of root directory. */
		if (!*req->path) {
			ret = www_serve_cmd(cfd, req);
			if (ret)
				ret = NULL;
			else
				return NULL;
		}

		tmp_fd = *req->path
			? openat(main_fd, req->path, O_RDONLY | O_CLOEXEC)
			: fcntl(main_fd, F_DUPFD_CLOEXEC, 0);
		if (tmp_fd < 0) {
			switch (errno) {
			case EPERM:
			case EACCES:
				ret = HTTP_403_FORBIDDEN;
				goto out;

			case ENOENT:
				ret = HTTP_404_NOT_FOUND;
				goto out;

			default:
				ret = HTTP_500_INTERNAL_SERVER_ERROR;
				goto out;
			}
		} else if (fstat(tmp_fd, &st) < 0) {
			ret = HTTP_500_INTERNAL_SERVER_ERROR;
			goto out;
		}
	} else if (S_ISREG(st.st_mode)) {
		if (*req->path)
			return HTTP_404_NOT_FOUND;
	}

	if (S_ISDIR(st.st_mode)) {
		char const *header = www_get_header(req, "ACCEPT");
		if (header && !!strstr(header, "html"))
			accept = A_HTML;

		dir = fdopendir(tmp_fd);
		if (!dir) {
			ret = HTTP_500_INTERNAL_SERVER_ERROR;
			goto out;
		}

		char const *mime_type;
		switch (accept) {
		case A_PLAIN: mime_type = "text/plain"; break;
		case A_HTML:  mime_type = "text/html"; break;
		default:
			abort();
		}

		headers_size = sprintf(headers,
				"HTTP/1.1 200 OK\r\n"
				"Date: %s\r\n"
				"Last-Modified: %s\r\n"
				"Content-Type: %s; charset=UTF-8\r\n"
				"Connection: close\r\n"
				"Transfer-Encoding: chunked\r\n"
				"\r\n",
				date,
				last_modified,
				mime_type);
	} else if (0 <= tmp_fd) {
		fd = tmp_fd;
	}

	if (!S_ISDIR(st.st_mode)) {
		char const *range = www_get_header(req, "RANGE");
		if (range)
			sscanf(range, "bytes=%ld-%ld", &offset, &end_offset);

		if (st.st_size < end_offset)
			end_offset = st.st_size;

		headers_size = snprintf(headers, sizeof headers,
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
		if ((int)sizeof headers <= headers_size) {
			ret = HTTP_500_INTERNAL_SERVER_ERROR;
			goto out;
		}
	}

	if (www_write(cfd, headers, headers_size) < 0) {
		ret = HTTP_500_INTERNAL_SERVER_ERROR;
		goto out;
	}

	if (strcmp(req->method, "GET"))
		goto out;

	if (S_ISDIR(st.st_mode)) {
		char buf[100 + PATH_MAX + PATH_MAX + NAME_MAX + NAME_MAX];
		int buf_size;

		if (A_HTML == accept) {
			buf_size = snprintf(buf, sizeof buf,
					"<!DOCTYPE html>\n"
					"<html>\n"
					"<head>\n"
					"\t<title>/%.*s</title>\n"
					"\t<style>\n"
					"\t\tul { list-style: none; padding-left: 0; }\n"
					"\t\ta:not(:hover) { text-decoration: none; }\n"
					"\t</style>\n"
					"</head>\n"
					"<body>\n"
					"\t<pre>"
					"<h1>Index of /%s</h1>"
					"<ul>",
					PATH_MAX, req->path,
					req->path); /* Could be longer because of ./..///dir/././. */
			if ((int)sizeof buf <= buf_size ||
			    www_write_chunked(cfd, buf, buf_size) < 0)
				goto out;
		}

		rewinddir(dir);

		for (struct dirent *dent; (dent = readdir(dir));) {
			if ('.' == dent->d_name[0] && !dent->d_name[1 + ('.' == dent->d_name[1])])
				continue;

			if (A_HTML == accept) {
				char class = '?';
				switch (dent->d_type) {
				case DT_BLK:  class = '#'; break;
				case DT_CHR:  class = '~'; break;
				case DT_DIR:  class = '/'; break;
				case DT_FIFO: class = '|'; break;
				case DT_LNK:  class = '@'; break;
				case DT_REG:  class = ' '; break;
				case DT_SOCK: class = '='; break;
				}
				buf_size = sprintf(buf, "<li><a href=\"/%s%s%s\">%s</a>%c</li>",
						req->path, *req->path ? "/" : "", dent->d_name, dent->d_name, class);
			} else {
				buf_size = sprintf(buf, "%s\n", dent->d_name);
			}

			if (www_write_chunked(cfd, buf, buf_size) < 0)
				goto out;
		}

		if (A_HTML == accept) {
			buf_size = sprintf(buf,
					"</ul>"
					"</pre>\n"
					"</body>\n"
					"</html>\n");
			if (www_write_chunked(cfd, buf, buf_size) < 0)
				goto out;
		}
		if (www_write_chunked(cfd, "", 0) < 0)
			goto out;
	} else if (S_ISREG(st.st_mode)) {
		if (sendfile(cfd, fd, &offset, end_offset - offset) < 0) {
			www_log(ERROR, "Failed to send file: %s", strerror(errno));
			goto out;
		}
	}

out:
	if (dir)
		/* Also closes tmp_fd. */
		closedir(dir);
	else if (0 <= tmp_fd)
		close(tmp_fd);

	return ret;
}

static void *
www_worker(void *arg)
{
	atomic_fetch_add_explicit(&nb_clients, 1, memory_order_relaxed);

	int cfd = (int)(uintptr_t)arg;

	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} csa;

	struct timespec start;
	clock_gettime(CLOCK_MONOTONIC, &start);

	struct sockaddr *csa_sa = 0 <= getpeername(cfd, &csa.sa, &(socklen_t){ sizeof csa }) ? &csa.sa : NULL;

	www_log(DEBUG, "Hello %s", www_straddr(csa_sa));

	char const *status;
	HTTPRequest req;
	if ((status = www_parse_request(cfd, &req)) ||
	    (status = www_serve_file(cfd, &req)))
		www_write_response(cfd, status);

	struct timespec end;
	clock_gettime(CLOCK_MONOTONIC, &end);

	shutdown(cfd, SHUT_RDWR);
	close(cfd);

	www_log(DEBUG, "Bye %s (alive for %1.3f seconds)", www_straddr(csa_sa),
			(double)((end.tv_sec - start.tv_sec) * NSEC_PER_SEC + (end.tv_nsec - start.tv_nsec)) / NSEC_PER_SEC);

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

	if (!(shell = getenv("SHELL")))
		shell = "sh";

	if (setrlimit(RLIMIT_FSIZE, &(struct rlimit const) { .rlim_cur = 0, .rlim_max = 0, }) < 0 ||
	    setrlimit(RLIMIT_NOFILE, &(struct rlimit const) { .rlim_cur = 20, .rlim_max = 20, }) < 0)
		www_log(FATAL, "Failed to set resource limit: %s", strerror(errno));

	nice(+10);

	char const *path = 1 < argc ? argv[1] : "index.html";
	if ((filename = strrchr(path, '/')))
		++filename;
	else
		filename = path;

	if ((main_fd = open(path, O_CLOEXEC | O_RDONLY)) < 0)
		www_log(DEBUG, "%s: %s", path, strerror(errno));

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
			www_log(ERROR, "Failed to bind to %s", www_straddr(ai->ai_addr));
			close(sfd);
			continue;
		}

		if (listen(sfd, 2) < 0) {
			www_log(FATAL, "Failed to listen on %s: %s", www_straddr(ai->ai_addr), strerror(errno));
			close(sfd);
			continue;
		}

		www_log(DEBUG, "Listening on http://%s%s%s%s",
				www_straddr(ai->ai_addr),
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
		if (pthread_create(&thread, NULL, www_worker, (void *)(uintptr_t)cfd)) {
			close(cfd);
			www_log(ERROR, "Failed to create worker: %s", strerror(errno));
		}
	}

	return EXIT_FAILURE;
}
