#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <signal.h>
#include <sys/time.h>

#define PORT 8080
#define ROOT_DIR "./web"
#define MAX_CLIENTS 100
#define LOG_FILE "server.log"
#define SEND_TIMEOUT 5

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

struct
{
    char *ext;
    char *mime;
} mime_types[] = {
    {".mp4", "video/mp4"},
    {".mp3", "audio/mpeg"},
    {".ts", "video/mp2t"},
    {".mkv", "video/x-matroska"},
    {".html", "text/html"},
    {".js", "text/javascript"},
    {".zip", "application/zip"},
    {".jpg", "image/jpeg"},
    {".json", "application/json"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {NULL, "application/octet-stream"}
};

void write_log(const char *client_ip, const char *request_path, int status_code)
{
    time_t now;
    time(&now);
    char time_str[20];
    strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));

    pthread_mutex_lock(&log_mutex);
    FILE *log_fp = fopen(LOG_FILE, "a");
    if (log_fp)
    {
        fprintf(log_fp, "[%s] %s %s %d\n", time_str, client_ip, request_path, status_code);
        fclose(log_fp);
    }
    pthread_mutex_unlock(&log_mutex);
}

const char *get_mime_type(const char *path)
{
    const char *ext = strrchr(path, '.');
    if (ext)
    {
        for (int i = 0; mime_types[i].ext; i++)
        {
            if (strcmp(ext, mime_types[i].ext) == 0)
                return mime_types[i].mime;
        }
    }
    return mime_types[sizeof(mime_types) / sizeof(mime_types[0]) - 1].mime;
}

void send_headers(int client_sock, int status, const char *status_str,
                    const char *content_type, long content_length, int accept_ranges)
{
    char buffer[1024];
    snprintf(buffer, sizeof(buffer),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n",
            status, status_str, content_type, content_length);
    if (accept_ranges)
    {
        strcat(buffer, "Accept-Ranges: bytes\r\n");
    }
    strcat(buffer, "Connection: close\r\n\r\n");

    if (send(client_sock, buffer, strlen(buffer), MSG_NOSIGNAL) == -1)
    {
        write_log("unknown", "header_send", 499);
    }
}

int handle_range_request(int client_sock, int fd, const char *range_header,
                         off_t file_size, const char *client_ip, const char *path, const char *mime_type)
{
    long start = 0, end = 0;
    if (sscanf(range_header, "bytes=%ld-%ld", &start, &end) != 2)
    {
        return -1;
    }
    if (end == 0)
        end = file_size - 1;

    if (start < 0 || end >= file_size || start > end)
    {
        send_headers(client_sock, 416, "Range Not Satisfiable", "text/plain", 16, 0);
        send(client_sock, "416 Range Error\n", 16, MSG_NOSIGNAL);
        write_log(client_ip, path, 416);
        return -1;
    }

    char headers[512];
    snprintf(headers, sizeof(headers),
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Range: bytes %ld-%ld/%ld\r\n"
            "Content-Length: %ld\r\n"
            "Content-Type: %s\r\n\r\n",
            start, end, file_size, end - start + 1, mime_type);
    send(client_sock, headers, strlen(headers), MSG_NOSIGNAL);

    lseek(fd, start, SEEK_SET);
    char buffer[4096];
    long remain = end - start + 1;
    while (remain > 0)
    {
        int read_bytes = read(fd, buffer, sizeof(buffer));
        if (read_bytes <= 0)
            break;
        ssize_t sent = send(client_sock, buffer, read_bytes, MSG_NOSIGNAL);
        if (sent <= 0)
        {
            if (errno == EPIPE)
            {
                write_log(client_ip, path, 499);
                break;
            }
        }
        remain -= read_bytes;
    }
    return 0;
}

int is_connection_alive(int sock)
{
    char buf[1];
    ssize_t ret = recv(sock, buf, 1, MSG_PEEK | MSG_DONTWAIT);
    if (ret == 0)
        return 0;
    if (ret == -1)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 1 : 0;
    return 1;
}

void handle_file(int client_sock, const char *path, const char *range_header, const char *client_ip)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        send_headers(client_sock, 404, "Not Found", "text/plain", 13, 0);
        send(client_sock, "404 Not Found\n", 13, MSG_NOSIGNAL);
        write_log(client_ip, path, 404);
        return;
    }

    struct stat st;
    fstat(fd, &st);
    const char *mime_type = get_mime_type(path);

    // 视频/音频传输优化设置
    if (strstr(mime_type, "video/") || strstr(mime_type, "audio/"))
    {
        int buf_size = 1024 * 1024;
        setsockopt(client_sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(int));
        int flag = 1;
        setsockopt(client_sock, IPPROTO_TCP, O_NDELAY, &flag, sizeof(int));
    }

    if (range_header && (strstr(mime_type, "video/") || strstr(mime_type, "audio/")))
    {
        if (handle_range_request(client_sock, fd, range_header, st.st_size, client_ip, path, mime_type) == 0)
        {
            close(fd);
            return;
        }
    }

    send_headers(client_sock, 200, "OK", mime_type, st.st_size, strstr(mime_type, "video/") != NULL || strstr(mime_type, "audio/") != NULL);

    off_t offset = 0;
    while (offset < st.st_size)
    {
        if (!is_connection_alive(client_sock))
        {
            write_log(client_ip, path, 499);
            break;
        }

        ssize_t sent = sendfile(client_sock, fd, &offset, st.st_size - offset);
        if (sent > 0)
            continue;

        if (sent == -1)
        {
            if (errno == EPIPE)
            {
                write_log(client_ip, path, 499);
                break;
            }
            if (errno == EAGAIN || errno == EINTR)
            {
                usleep(1000);
                continue;
            }
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "sendfile error: %s", strerror(errno));
            write_log(client_ip, err_msg, 500);
            break;
        }
        if (sent == 0)
        { // Connection might be closed gracefully
            break;
        }
    }
    close(fd);
}

void generate_dir_listing(int client_sock, const char *path, const char *client_ip)
{
    DIR *dir = opendir(path);
    if (!dir)
    {
        send_headers(client_sock, 403, "Forbidden", "text/plain", 13, 0);
        send(client_sock, "403 Forbidden\n", 13, MSG_NOSIGNAL);
        write_log(client_ip, path, 403);
        return;
    }

    char buffer[4096];
    int len = snprintf(buffer, sizeof(buffer),
                        "<html><head><title>Index of %s</title></head>"
                        "<body><h1>Index of %s</h1><ul>",
                        path, path);

    struct dirent *entry;
    while ((entry = readdir(dir)))
    {
        if (strcmp(entry->d_name, ".") == 0)
            continue;
        len += snprintf(buffer + len, sizeof(buffer) - len,
                        "<li><a href=\"%s\">%s</a></li>", entry->d_name, entry->d_name);
    }
    snprintf(buffer + len, sizeof(buffer) - len, "</ul></body></html>");
    closedir(dir);

    send_headers(client_sock, 200, "OK", "text/html", strlen(buffer), 0);
    send(client_sock, buffer, strlen(buffer), MSG_NOSIGNAL);
    write_log(client_ip, path, 200);
}

void *handle_client(void *arg)
{
    int client_sock = *(int *)arg;
    char buffer[4096], path[1024], method[16], protocol[16];
    char range_header[256] = {0};

    ssize_t bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0)
    {
        close(client_sock);
        free(arg);
        return NULL;
    }
    buffer[bytes_read] = '\0'; // Ensure null termination

    if (sscanf(buffer, "%15s %1023s %15s", method, path, protocol) != 3)
    {
        // Handle malformed request
        send_headers(client_sock, 400, "Bad Request", "text/plain", 11, 0);
        send(client_sock, "Bad Request\n", 11, MSG_NOSIGNAL);
        write_log("unknown", "malformed_request", 400);
        close(client_sock);
        free(arg);
        return NULL;
    }

    char *range_ptr = strstr(buffer, "Range: ");
    if (range_ptr)
    {
        sscanf(range_ptr, "Range: %255s", range_header);
    }

    char full_path[2048];
    snprintf(full_path, sizeof(full_path), "%s%s", ROOT_DIR, path);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_sock, (struct sockaddr *)&addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));

    struct stat st;
    if (stat(full_path, &st) != 0)
    {
        send_headers(client_sock, 404, "Not Found", "text/plain", 13, 0);
        send(client_sock, "404 Not Found\n", 13, MSG_NOSIGNAL);
        write_log(client_ip, path, 404);
    }
    else if (S_ISDIR(st.st_mode))
    {
        generate_dir_listing(client_sock, full_path, client_ip);
    }
    else
    {
        handle_file(client_sock, full_path, range_header, client_ip);
    }

    close(client_sock);
    free(arg);
    return NULL;
}

int main()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGPIPE);
    if (sigaction(SIGPIPE, &sa, NULL) == -1)
    {
        perror("sigaction");
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket");
        return 1;
    }
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        perror("setsockopt reuseaddr");
        close(server_fd);
        return 1;
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1)
    {
        perror("setsockopt reuseport");
        close(server_fd);
        return 1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = INADDR_ANY};

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, MAX_CLIENTS) == -1)
    {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("Server running on port %d\n", PORT);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_sock = malloc(sizeof(int));
        if (!client_sock)
        {
            perror("malloc");
            continue;
        }
        *client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (*client_sock == -1)
        {
            perror("accept");
            free(client_sock);
            continue;
        }

        struct timeval tv;
        tv.tv_sec = SEND_TIMEOUT;
        tv.tv_usec = 0;
        if (setsockopt(*client_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1)
        {
            perror("setsockopt send timeout");
            close(*client_sock);
            free(client_sock);
            continue;
        }

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client_sock) != 0)
        {
            perror("pthread_create");
            close(*client_sock);
            free(client_sock);
            continue;
        }
        pthread_detach(thread);
    }

    close(server_fd);
    return 0;
}