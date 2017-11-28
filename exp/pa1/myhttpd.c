#include "http.h"

#define CHECK_BLANK(idx, buf) \
	(buf[idx] == ' ' || buf[idx] == '\n' || buf[idx] == '\r')

/* socket buffer */
char sock_buf[4096] = {0};
/* http version:1.0 or 1.1 */
unsigned version;
/* Port number */
unsigned port_num;
/* 
 * Time out in second 
 * =0 for http 1.0
 * >0 for http 1.1
 */
unsigned timeout;

/* 400 Bad Request */
char content_400[] = 
"<html><head>\n<title>400 Bad Request</title>\n</head><body>\n"
"<h1>Bad Request</h1><p>The browser (or proxy) sent a request "
"that this server could not understand.</p>\n"
"</body></html>";

/* 403 forbidden */
char content_403[] = 
"<html><head>\n<title>403 - Forbidden</title>\n</head><body>\n"
"<h1>Forbidden</h1>"
"<p>You do not have permission to access the requested address (URL).</p>\n"
"</body></html>";

/* 404 not found content */
char content_404[] = 
"<html><head>\n<title>404 Not Found</title>\n</head><body>\n"
"<h1>Not Found</h1>\nThe requested URL was not found on this server.\n"
"</body></html>\n\0";

void error(char *err_msg)
{
	printf("%s", err_msg);
	exit(1);
}

void dump_buf(char *buf, int len, int file_size)
{
	int i, count, write_size = 1048576;
	int j;

	if (file_size >= write_size)
		count = 1;
	else
		count = write_size / file_size;

	for (i=0; i<count; i++) {
		for (j=0; j<len; j++) {
			fprintf(stderr, "%x ", (int)buf[j]);
		}
		fprintf(stderr, "\n");
	}
}

int get_time(char *buf)
{
	time_t curtime;
	struct tm *loctime;
	int len;

	/* Get the current time. */
	curtime = time(NULL);

	/* Convert it to local time representation. */
	loctime = localtime(&curtime);

	/* Print out the date and time in the standard format. */
	len = sprintf(buf, "%s", asctime(loctime));

	/* asctime will put a '\n' at the end of string */
	buf[len-1] = '\n';
	buf[len] = '\0';

	return strlen(buf);
}

char *get_file_ext(char *filename) {
	char *e = strrchr(filename, '.');
	if (e == NULL)
		e = ""; 
	return e;
}

int get_200_ok(char *buf, char *file_ext, int file_len)
{
	int main_ver = 1;
	int minor_ver = 0;
	int cc = 0;

	if (version == 11)
		minor_ver = 1;

	cc += sprintf(buf, "HTTP/%d.%d 200 OK\n", main_ver, minor_ver);

	if (strcmp(file_ext, ".html") == 0) {
		cc += sprintf(&buf[cc], "Content-Type: text/html\n");
	} else if (strcmp(file_ext, ".jpeg") == 0 ||
			   strcmp(file_ext, ".jpg") == 0)
	{
		cc += sprintf(&buf[cc], "Content-Type: image/%s\n", file_ext);
	} else if (strcmp(file_ext, ".gif") == 0) {
		cc += sprintf(&buf[cc], "Content-Type: image/gif\n");
	} else if (strcmp(file_ext, ".ico") == 0) {
		cc += sprintf(&buf[cc], "Content-Type: image/x-icon\n");
	} else {
		fprintf(stderr, "ERROR:Undefined file extension %s\n", file_ext);
		error("");
	}
	
	cc += sprintf(&buf[cc], "Content-Length: %d\n", file_len);

	if (version == 10) {
		cc += sprintf(&buf[cc], "Connection: Close\n\n");
	} else {
		cc += sprintf(&buf[cc], "Keep-Alive: timeout=%d, max=%d\n",
				timeout, timeout);
		cc += sprintf(&buf[cc], "Connection: Keep-Alive\n\n");
	}

	return cc;
}

int get_400_bad_request(char *buf)
{
	int main_ver = 1;
	int minor_ver = 0;
	int cc = 0;

	cc += sprintf(buf, "HTTP/%d.%d 400 Bad Request\n", main_ver, minor_ver);
	cc += sprintf(&buf[cc], "Content-Length: %d\n", strlen(content_400));
	cc += sprintf(&buf[cc], "Connection: close\n");
	cc += sprintf(&buf[cc], "Content-Type: text/html\n\n");
	cc += sprintf(&buf[cc], "%s\0", content_400);
}

int get_403_forbidden(char *buf)
{
	int main_ver = 1;
	int minor_ver = 0;
	int cc = 0;

	cc += sprintf(buf, "HTTP/%d.%d 403 Forbidden\n", main_ver, minor_ver);
	cc += sprintf(&buf[cc], "Content-Length: %d\n", strlen(content_403));
	cc += sprintf(&buf[cc], "Connection: close\n");
	cc += sprintf(&buf[cc], "Content-Type: text/html\n\n");
	cc += sprintf(&buf[cc], "%s\0", content_403);
}

int get_404_not_found(char *buf)
{
	int main_ver = 1;
	int minor_ver = 0;
	int cc = 0;
	
	if (version == 11)
		minor_ver = 1;

	cc += sprintf(buf, "HTTP/%d.%d 404 Not Found\n", main_ver, minor_ver);
	cc += sprintf(&buf[cc], "Content-Length: %d\n", strlen(content_404));
	cc += sprintf(&buf[cc], "Connection: close\n");
	cc += sprintf(&buf[cc], "Content-Type: text/html\n\n");
	cc += sprintf(&buf[cc], "%s\0", content_404);

	return cc;
}

/* 
 * Try to read data from fd
 */
int try_read(int fd, char* read_buf, int read_len)
{
	int read_cnt;
	int offset;
	
	read_cnt = read(fd, (void *)read_buf, read_len);
	
	if (read_cnt < 0) {
		if (errno == EAGAIN)
			return 0;
		fprintf(stderr, "ERROR:Read error with errno=%d %d\n", errno, fd);
		fflush(stderr);
		return 0;
	}

	return read_cnt;
}

int try_write(int fd, char *write_buf, int write_len)
{
	int write_cnt;
	int offset;

	write_cnt = write(fd, (void *)write_buf, write_len);

	if (write_cnt != write_len) {
		if (errno == ECONNRESET)
			return 0;
		fprintf(stderr, "ERROR:Write error with errno=%d, "
			"write_cnt:%d != write_len:%d\n", errno, write_cnt, write_len);
		fflush(stderr);
		return 0;
	}

	return write_cnt;
}

void send_error(int fd, int cc)
{
	char buf[512] = {0};

	if (cc < 400)
		return;

	switch (cc) {
		case 400:
			get_400_bad_request(buf);
			break;
		case 403:
			get_403_forbidden(buf);
			break;
		case 404:
			get_404_not_found(buf);
			break;
	}
	try_write(fd, buf, strlen(buf));
}

int open_file_for_write(char *filename, int sfd)
{
	int ffd;
	int file_size;
	char buf[1024];
	int saturate = 0;

	if (strcmp(filename, "./") == 0) {
		strcpy(filename, "./index.html");
	} 
	
	ffd = open(filename, O_RDONLY);

	if (ffd < 0) { /* Failed and send 404 */
		fprintf(stderr, "ERROR:Cannot open file %s, errno=%d\n", 
			filename, errno);
		if (errno == EACCES) {
			return -403;
		} else {
			return -404;
		}
	} 

	file_size = lseek(ffd, 0, SEEK_END);
	lseek(ffd, 0, SEEK_SET);

	if (file_size == 75672)
		saturate = 1;

	/* Send 200 OK at first */
	get_200_ok(buf, get_file_ext(filename), file_size);
	try_write(sfd, buf, strlen(buf));

	while (file_size) {
		ssize_t read_cnt = try_read(ffd, buf, sizeof(buf));

		if (saturate)
			dump_buf(buf, read_cnt, file_size);

		if (read_cnt) {
			if (try_write(sfd, buf, read_cnt) == 0) {
				close(ffd);
				return -1;
			}
		}
		file_size -= read_cnt;
	}

	close(ffd);
	return 0;
}

int handle_get(char *path, char *cli_ver, int fd)
{
	char buf[256];
	int state = 0;
	int idx = 0;

	/* Check and get file name */
	if (!path || *path != '/')
		return -400;

	sscanf(path, "%s", &buf[1]);
	buf[0] = '.';

	/* Check client version */
	if (!cli_ver || strlen(cli_ver) != 8 || 
		(strcmp(cli_ver, "HTTP/1.0") != 0 && strcmp(cli_ver, "HTTP/1.1")) != 0)
		return -400;

	/* Send response */
	return open_file_for_write(buf, fd);
}

/* Respond to client */
int serve_client(int fd, int infinite)
{
	int read_cnt;
	int get_request = 1; /* It should be 1 by default */
	int cc;

	//printf("Serve client\n");
	do {
		read_cnt = try_read(fd, sock_buf, sizeof(sock_buf));
	
		if (read_cnt == 0) {
			printf("Close connection\n");
			return -1;
		}

		char *p_req[3];

		/* Get request, path, and version one by one */
		p_req[0] = strtok(sock_buf," \r\n");
		p_req[1] = strtok(NULL, " \r\n");
		p_req[2] = strtok(NULL, " \r\n");

		/* Process request */
		if (p_req[0] && strlen(p_req[0]) == 3 && 
			strcmp(p_req[0], "GET") == 0) 
		{
			if ((cc = handle_get(p_req[1], p_req[2], fd)) < 0)
				goto bail;
		} else {
			cc = -400;
			goto bail;
		}
		
		if (version == 10)
			break;

	} while (infinite);

	//printf("Done serve client\n");

	return 0;
bail:
	printf("Error condition code=%d\n", cc);
	send_error(fd, 0-cc);
	return -1;
}

#ifdef FORK

/* Server main function */
void run()
{
	int sfd, clilen, n;
	struct sockaddr_in serv_addr, cli_addr;

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (sfd < 0)
		error("ERROR:Cannot open socket\n");

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_port = htons(port_num);

	serv_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR:Cannot bind\n");

	listen(sfd, SERVER_MAX_LISTEN);

	clilen = sizeof(cli_addr);

	signal(SIGCHLD, SIG_IGN);

	while (1) {
		pid_t pid;
		int newfd;

		newfd = accept(sfd, (struct sockaddr *) &cli_addr, &clilen);

		if (newfd < 0)
			error("ERROR:Cannot accept\n");
#if 0
		printf("FORK:connect from host=%s, port=%u, sockfd=%d\n",
				inet_ntoa(cli_addr.sin_addr),
				ntohs(cli_addr.sin_port),
				newfd);
#endif	
		pid = fork();
		
		if (pid < 0)
			error("ERROR:Cannot fork\n");

		/* Child process */
		if (pid == 0)  {
			struct timeval tv;

			/* Set timeout value */
			tv.tv_sec = timeout;  
			tv.tv_usec = 0; 
			setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, 
				(char *)&tv, sizeof(struct timeval));

			close(sfd);
			serve_client(newfd, 1);
			exit(0);
		} else {
			close(newfd);
		}
	}
}
#else
/* Time table for recording beginning time of each connected socket */
struct socket_info {
	int connected;
	time_t begin_time;
};

struct socket_info sock_info[FD_SETSIZE];

void run()
{
	fd_set active_sock_set, read_sock_set;
	int sfd, clilen;
	struct sockaddr_in serv_addr, cli_addr;
	struct timeval select_timeout;

	/* Create the socket and set it up to accept connections. */
	sfd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (sfd < 0)
		error("ERROR:Cannot open socket\n");

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_port = htons(port_num);

	serv_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR:Cannot bind\n");

	listen(sfd, SERVER_MAX_LISTEN);

	clilen = sizeof(cli_addr);

	/* Initialize the set of active sockets. */
	FD_ZERO(&active_sock_set);
	FD_SET(sfd, &active_sock_set);

	/* Initialize timeout value to 1 sec */
	if (version == 11) {
		select_timeout.tv_sec = 1;
		select_timeout.tv_usec = 0;
		memset(sock_info, 0, sizeof(sock_info));
	}

	signal(SIGPIPE, SIG_IGN);

	while (1) {
		int status;
		int i;

		/* Block until input arrives on one or more active sockets. */
		read_sock_set = active_sock_set;

		status = select(FD_SETSIZE, &read_sock_set, NULL, NULL, 
					(version == 11) ? &select_timeout : NULL);

		if (status < 0) {
			error("Select failure");
		} else if (status == 0) { 
			time_t curr_time = time(NULL);
			
			assert(version == 11);

			/* select timeout and check for socket timeout */
			for (i=0; i<FD_SETSIZE; i++) {
				if (sock_info[i].connected) {
					time_t passed_time;
							
					passed_time = curr_time - sock_info[i].begin_time;

					printf("%d %d\n", i, passed_time);
					if (passed_time >= timeout) {
						printf("Close connection for timeout\n");
						close(i);
						sock_info[i].connected = 0;
						FD_CLR(i, &active_sock_set);
					} 
				}
			}

			select_timeout.tv_sec = 1;
			select_timeout.tv_usec = 0;

			continue;
		}

		/* Service all the sockets with input pending. */
		for (i=0; i<FD_SETSIZE; i++) {
			if (FD_ISSET(i, &read_sock_set)) {
				if (i == sfd) {
					/* Connection request on original socket. */
					int newfd;
					
					newfd = accept(sfd, (struct sockaddr *)&cli_addr, &clilen);
					
					if (newfd < 0)
						error("ERROR:Cannot accept\n");
					
					printf("SELECT:connect from host=%s, port=%u, sockfd=%d\n",
						inet_ntoa(cli_addr.sin_addr),
						ntohs(cli_addr.sin_port),
						newfd);

					FD_SET(newfd, &active_sock_set);
					sock_info[newfd].connected = 1;
					sock_info[newfd].begin_time = time(NULL);
				} else {
					int cc;

					/* Data arriving on an already-connected socket. */
					cc = serve_client(i, 0);

					sock_info[i].begin_time = time(NULL);
			
					if (version == 10 || cc < 0) {
						close(i);
						FD_CLR(i, &active_sock_set);
						sock_info[i].connected = 0;
					}
				}
			}
		}
	}
}

# endif

int main(int argc, char *argv[])
{
	char *ptr;

	if (argc < 4) {
		error("USAGE:myhttpd <httpversion> <portnumber> <timeout>\n");
	}

	ptr = argv[1];

	if (ptr[0] == '1' &&
		(ptr[1] == 0 || (ptr[1] == '.' && ptr[2] == '0'))) 
	{
		version = 10;
	} else if (ptr[0] == '1' && ptr[1] == '.' && ptr[2] == '1') {
		version = 11;
	} else {
		error("ERROR:Specified version not supported\n");
	}

	ptr = argv[2];

	port_num = atoi(ptr);

	if (port_num < 1024 || port_num > 65536) {
		error("ERROR:Port number must between 1024 and 65536\n");
	}

	ptr = argv[3];

	timeout = atoi(ptr);

	if (version == 10 && timeout != 0) {
		error("ERROR:Timeout of http 1.0 must be zero\n");
	} else if (version == 11 && timeout <= 0) {
		error("ERROR:Timeout of http 1.1 must be greater than zero\n");
	}

	/* Start server */
	//printf("SERVER START\n");
	run();
	printf("SERVER END\n");

	return 0;
}
