#include "http.h"

#ifdef SATURATION
#define FILE_COUNTER 100000000
#else
#define FILE_COUNTER 200
#endif

/* HTTP version */
int version;
/* Port number */
int port_num;
/* Server url address */
char *server_url;
/* spcket buffer */
char sock_buf[4096];
/* Time used for connection, in nanoseconds */
unsigned long long connection_time;
unsigned long long connection_counter;
/* Time used for transmission, in nanoseconds */
unsigned long long transmission_time;
unsigned long long transmission_length;
volatile void *record_table;
pthread_mutex_t table_mutex;
/* Size of file */
int file_size;

void error(char *err_msg)
{
	printf("%s", err_msg);
	exit(1);
}

void dump_buf(char *buf, int len)
{
	int i;

	printf("dump length=%d\n", len);

	for (i=0; i<len; i++) {
		printf("%x", buf[i]);
	}
	printf("\n");
}

int connect_server()
{
	int sfd;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	struct in_addr **addr_list;
	int i;
	struct timespec begin;
	struct timespec end;

	/* Create a socket point */
	sfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sfd < 0) {
		error("ERROR:Cannot open socket\n");
	}
	
	server = gethostbyname(server_url);

	if (!server) {
		error("ERROR:No such host\n");
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, 
		(char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(port_num);

	clock_gettime(CLOCK_MONOTONIC, &begin);
	/* Now connect to the server */
	if (connect(sfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
		fprintf(stderr, "ERROR:Cannot connect, errno=%d\n", errno);
		error("");
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	connection_time += BILLION * (end.tv_sec - begin.tv_sec) + 
		(end.tv_nsec - begin.tv_nsec);
	
	connection_counter++;

	return sfd;
}

int try_write(int fd, char *write_buf, int write_len)
{
	int write_cnt;
	int offset;
	struct timespec begin;
	struct timespec end;

	clock_gettime(CLOCK_MONOTONIC, &begin);
	write_cnt = write(fd, (void *)write_buf, write_len);
	clock_gettime(CLOCK_MONOTONIC, &end);

	if (write_cnt) {
		transmission_time += BILLION * (end.tv_sec - begin.tv_sec) + 
			(end.tv_nsec - begin.tv_nsec);
		transmission_length += write_cnt;
	}

	if (write_cnt != write_len) {
		fprintf(stderr, "ERROR:Write error with errno=%d, "
			"write_cnt:%d != write_len:%d\n", errno, write_cnt, write_len);
		return 0;
	}
	return write_cnt;
}

int try_read(int fd, char* read_buf, int read_len)
{
	int read_cnt;
	int offset;
	struct timespec begin;
	struct timespec end;
	
	clock_gettime(CLOCK_MONOTONIC, &begin);

	read_cnt = read(fd, (void *)read_buf, read_len);
	
	clock_gettime(CLOCK_MONOTONIC, &end);
	
	if (read_cnt < 0) {
		if (errno == EAGAIN)
			return 0;
		fprintf(stderr, "ERROR:Read error with errno=%d\n", errno);
		return 0;
	}

	if (read_cnt) {
		transmission_time += BILLION * (end.tv_sec - begin.tv_sec) + 
			(end.tv_nsec - begin.tv_nsec);
		transmission_length += read_cnt;
	}

	return read_cnt;
}

void run(int download)
{
	int sfd;
	int i;
	int total_read = 0;
	long long *p_table = (long long *) record_table;

	sfd = connect_server();

	while (1) {
		int read_cnt;
		int get_header = 1;
		int left_len;

#ifdef SATURATION
		sprintf(sock_buf, "GET /pics/pic_mountain.jpg HTTP/1.%d\n\n\0", 
			(version == 10) ? 0 : 1);
#else
		sprintf(sock_buf, "GET /pics/sbob.jpg HTTP/1.%d\n\n\0", 
			(version == 10) ? 0 : 1);
#endif

		try_write(sfd, sock_buf, strlen(sock_buf));
		
		while (1) {
			read_cnt = try_read(sfd, sock_buf, sizeof(sock_buf));

			if (read_cnt && get_header) {
				char *ptr;
				int read_content_len;
				int content_len;
				
				ptr = strstr(sock_buf, "200 OK");
				if (!ptr) {
					fprintf(stderr, "%s\n", sock_buf);
					error("ERROR:Cannot get specified file");
				}
				get_header = 0;

				ptr = strstr(sock_buf, "Content-Length: ");
				content_len = atoi(&ptr[16]);
				file_size = content_len;

				/* Go to end of header and get left content length */
				ptr = strstr(sock_buf, "\n\n");
				read_content_len = 
					(sock_buf + read_cnt) - (ptr + 2);
				left_len = content_len - read_content_len; 
				total_read += read_content_len;
			} else {
				total_read += read_cnt;
				left_len -= read_cnt;
			}

			if (left_len <= 0) {
				break;
			} 
		}

		if (version == 10 || read_cnt == 0) {
			close(sfd);
			sfd = connect_server();
		}
		if (read_cnt)
			download--;

		if (download <= 0) {
			break;
		}
	}
}

/* Done by parent process */
void init()
{
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&table_mutex, &attr);
	
	connection_time = 0;
	connection_counter = 0;
	transmission_time = 0;
	transmission_length = 0;

	/* Allocate record table as shared memory */
	record_table = 
		mmap(0, 48, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);

	if (record_table == MAP_FAILED) {
		error("ERROR:Failed to allocate record table\n");
	}

	((unsigned long *)record_table)[4] = FILE_COUNTER;
}

/* Done by child process */
void fini()
{
	unsigned long long *p_table = (unsigned long long *) record_table;
	double time_in_sec;

	printf("Statistics for process %d\n", getpid());
	
	time_in_sec = (double)connection_time / (double)BILLION;
	printf("Connection:Counter=%llu Elapsed time=%llu(ns) %.17lf(s)\n", 
		connection_counter, connection_time, time_in_sec);
	printf("Avg %.17lf connection(s)/sec\n", 
		(((double)connection_counter) / time_in_sec));

	time_in_sec = (double)transmission_time / (double)BILLION;
	printf("transmission:Length=%llu bytes Elapsed time=%llu(ns) %.17lf(s)\n",
		transmission_length, transmission_time, time_in_sec);
	
	printf("transmission throughput = %lf Mbits/sec\n",
		(double)(transmission_length * 8 ) / time_in_sec / 1024.0 / 1024.0);
	
	printf("Avg %.17lf(s)/byte, %.17lf(s)/file, file_size=%d\n", 
		(time_in_sec / ((double)transmission_length)), 
		(time_in_sec / ((double)transmission_length)) * file_size, file_size);

	pthread_mutex_lock(&table_mutex);
	
	p_table[0] += connection_counter;
	p_table[1] += connection_time;
	p_table[2] += transmission_length;
	p_table[3] += transmission_time;
	p_table[4] = file_size;
		
	pthread_mutex_unlock(&table_mutex);
}

/* Done by parent process */
void report(int process_num)
{
	unsigned long long *p_table = (unsigned long long *) record_table;
	double time_in_sec;
	
	printf("Total Statistics for all\n");
	
	time_in_sec = (double)p_table[1] / (double)BILLION;
	printf("Connection:Counter=%llu Elapsed time=%llu(ns) %.17lf(s)\n", 
		p_table[0], p_table[1], time_in_sec);
	printf("Avg %.17lf connections/sec\n", 
		(((double)p_table[0])) / time_in_sec);

	time_in_sec = (double)p_table[3] / (double)BILLION;
	printf("transmission:Length=%llu bytes Elapsed time=%llu(ns) %.17lf(s)\n",
		p_table[2], p_table[3], time_in_sec);
}

int main(int argc, char *argv[])
{
	int i, process_num, status;
	char *ptr;

#ifdef SATURATION
	if (argc < 5) {
		error("USAGE:clg-sat <server> <port> <httpversion>"
			" <#spawned processes>\n");
	}
#else
	if (argc < 5) {
		error("USAGE:clg <server> <port> <httpversion>"
			" <#spawned processes>\n");
	}
#endif

	server_url = argv[1];

	port_num = atoi(argv[2]);
	
	if (port_num < 1024 || port_num > 65536) {
		error("ERROR:Port number must between 1024 and 65536\n");
	}
	
	ptr = argv[3];

	if (ptr[0] == '1' &&
		(ptr[1] == 0 || (ptr[1] == '.' && ptr[2] == '0'))) 
	{
		version = 10;
	} else if (ptr[0] == '1' && ptr[1] == '.' && ptr[2] == '1') {
		version = 11;
	} else {
		error("ERROR:Specified version not supported\n");
	}

	process_num = atoi(argv[4]);

	init();
	printf("CLIENT SART\n");

	struct timespec begin;
	struct timespec end;
	
	clock_gettime(CLOCK_MONOTONIC, &begin);
	for (i=0; i<process_num; i++) {
		pid_t pid;

		pid = fork();

		if (pid < 0)
			error("ERROR:Cannot fork\n");

		if (pid == 0) {
			int per_download = (FILE_COUNTER / process_num) + 
				(i == process_num - 1) * (FILE_COUNTER % process_num);
			run(per_download);
			fini();
			exit(0);
		}
	}
	while (wait(&status) > 0) {
		printf("Exit status %d\n", status);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	
	report(process_num);
	
	unsigned long long exec_time = BILLION * (end.tv_sec - begin.tv_sec) + 
		(end.tv_nsec - begin.tv_nsec);

	printf("CLIENT STOP, total execution time = %lf sec\n", 
		(double)exec_time / (double)BILLION);

	return 0;
}
