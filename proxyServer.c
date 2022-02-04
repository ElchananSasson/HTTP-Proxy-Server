#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "threadpool.h"

#define LEN 512
#define BUF_LEN 1024

typedef struct NodeHost {
    char *data;
    struct NodeHost *next;
} NodeHost;

typedef struct LinkList_Host {
    NodeHost *first;
    NodeHost *last;
    int size;
} LinkList_Host;

typedef struct NodeIP {
    char *data;
    int mask;
    struct NodeIP *next;
} NodeIP;

typedef struct LinkList_IP {
    NodeIP *first;
    NodeIP *last;
    int size;
} LinkList_IP;

typedef struct URL {
    char *hostName, *path, *fullPath;
} URL;

typedef struct argThread {
    int sd, unFilter;
    LinkList_Host *host_list;
    LinkList_IP *ip_list;
} argThread;

/**
 * Initialize the lists.
 * @param host Host Link list
 * @param ip IP Link list
 * @param fp File pointer
 */
void initLists(LinkList_Host *host, LinkList_IP *ip, FILE *fp) {
    if (host == NULL || ip == NULL) {
        fprintf(stderr, "Allocation failure: Memory allocation failed.\n");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    host->first = NULL;
    host->last = NULL;
    host->size = 0;
    ip->first = NULL;
    ip->last = NULL;
    ip->size = 0;
}

/**
 * Add data to new node at the end of the given link list.
 * @param LinkList_Host Host Link list to add data to
 * @param LinkList_IP IP Link list to add data to
 * @param type 0 to host, 1 to IP
 * @param data Pointer to dynamically allocated data
 * @param mask to know the subnet
 * @return 0 on success, 1 otherwise
 */
int add(LinkList_Host *host, LinkList_IP *ip, int type, char *data, int mask) {
    if (type == 0) { ///add to host list
        NodeHost *new_node = malloc(sizeof(NodeHost));
        if (new_node == NULL) {
            return 1;
        }
        *new_node = (NodeHost) {data, NULL};
        if (host->first == NULL) {
            host->first = new_node;
            host->last = new_node;
        } else {
            host->last->next = new_node;
            host->last = new_node;
        }
        host->size++;
    }
    if (type == 1) { /// add to ip list
        NodeIP *new_node = malloc(sizeof(NodeIP));
        if (new_node == NULL) {
            return 1;
        }
        *new_node = (NodeIP) {data, mask, NULL};
        if (ip->first == NULL) {
            ip->first = new_node;
            ip->last = new_node;
        } else {
            ip->last->next = new_node;
            ip->last = new_node;
        }
        ip->size++;
    }
    return 0;
}

/**
 * Check if there are web sites we would like to block.
 * @param fp File pointer
 * @return 1 no filter, 0 otherwise
 */
int checkFilter(FILE *fp) {
    int unFilter = 0;
    if (fseek(fp, 0L, SEEK_END) != 0) {
        perror("error: fseek\n");
        exit(EXIT_FAILURE);
    }
    int fileSize = (int) ftell(fp);
    if (fileSize == 0) {
        unFilter = 1;
        fclose(fp);
        return unFilter;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("error: fseek\n");
        exit(EXIT_FAILURE);
    }
    return unFilter;
}

/**
 * Prefix analysis of IP address.
 * @param ip IP address
 * @param mask Mask of the IP address
 */
void parseIp(char *ip, int mask) {
    char copy[16], *byte1, *byte2, *byte3, *byte4;
    memset(copy, '\0', 16);
    strncpy(copy, ip, strlen(ip));
    double whichByte;
    int num, bin = 256, andNum = 0;
    byte1 = strtok(copy, ".");
    byte2 = strtok(NULL, ".");
    byte3 = strtok(NULL, ".");
    byte4 = strtok(NULL, " ");
    whichByte = (double) mask / 8;
    mask %= 8;
    if (mask == 0) {
        andNum = 255;
    }
    for (int i = 0; i < mask; i++) {
        bin /= 2;
        andNum += bin;
    }
    if (whichByte >= 0 && whichByte <= 1) { ///in byte1
        byte2 = "0";
        byte3 = "0";
        byte4 = "0";
        num = (int) strtol(byte1, NULL, 10);
        num = num & andNum;
        sprintf(byte1, "%d", num);
    }
    if (whichByte > 1 && whichByte <= 2) { ///in byte2
        byte3 = "0";
        byte4 = "0";
        num = (int) strtol(byte2, NULL, 10);
        num = num & andNum;
        sprintf(byte2, "%d", num);
    }
    if (whichByte > 2 && whichByte <= 3) { ///in byte3
        byte4 = "0";
        num = (int) strtol(byte3, NULL, 10);
        num = num & andNum;
        sprintf(byte3, "%d", num);
    }
    if (whichByte > 3 && whichByte <= 4) { ///in byte4
        num = (int) strtol(byte4, NULL, 10);
        num = num & andNum;
        sprintf(byte4, "%d", num);
    }
    memset(ip, '\0', strlen(ip));
    sprintf(ip, "%s.%s.%s.%s", byte1, byte2, byte3, byte4);
}

/**
 * Fills the lists by hostName and IP.
 * @param fp File pointer
 * @param host Host Link list to add data to
 * @param ip IP Link list to add data to
 */
void makeFilter(FILE *fp, LinkList_Host *host, LinkList_IP *ip) {
    char *token, *mask, *line = NULL;
    size_t len = 0;
    int subnet, flag; /// 0 to Host, 1 to IP
    while (getline(&line, &len, fp) != -1) {
        if ((line[0] > 47) && (line[0] < 58)) { /// IP
            flag = 1;
            token = strtok(line, "/");
            mask = strtok(NULL, " ");
            subnet = (int) strtol(mask, NULL, 10);
            parseIp(token, subnet);
        } else { /// Host
            flag = 0;
            token = strtok(line, "\r\n");
        }
        char *tokenToAdd = (char *) malloc(strlen(token) + 1);
        if (tokenToAdd == NULL) {
            fprintf(stderr, "Allocation failure: Memory allocation failed.\n");
            exit(EXIT_FAILURE);
        }
        strcpy(tokenToAdd, token);
        tokenToAdd[strlen(token)] = '\0';
        if (flag == 0) {
            if (add(host, ip, 0, tokenToAdd, subnet) == 1) {
                fprintf(stderr, "Allocation failure: Memory allocation failed.\n");
                exit(EXIT_FAILURE);
            }
        }
        if (flag == 1) {
            if (add(host, ip, 1, tokenToAdd, subnet) == 1) {
                fprintf(stderr, "Allocation failure: Memory allocation failed.\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    free(line);
    fclose(fp);
}

/**
 * Free the link lists.
 * @param host Host Link list to free
 * @param ip IP Link list to free
 */
void free_LinkList(LinkList_Host *host, LinkList_IP *ip) {
    if (host != NULL) {
        NodeHost *headHost = host->first, *p;
        while (headHost != NULL) {
            p = headHost;
            headHost = headHost->next;
            free(p->data);
            p->data = NULL;
            free(p);
            p = NULL;
        }
        free(host);
    }
    if (ip != NULL) {
        NodeIP *headIP = ip->first, *q;
        while (headIP != NULL) {
            q = headIP;
            headIP = headIP->next;
            free(q->data);
            q->data = NULL;
            free(q);
            q = NULL;
        }
        free(ip);
    }
}

/**
 * Creates an error message based on the input value.
 * @param num type of the error
 * @param sd socket descriptor
 */
void handleError(char *buf, int num) {
    char html[100], type[50], notice[50];
    size_t len;
    memset(html, '\0', 100);
    memset(type, '\0', 50);
    memset(notice, '\0', 50);
    sprintf(html, "<HTML><HEAD><TITLE></TITLE></HEAD>\r\n<BODY><H4></H4>\r\n\r\n</BODY></HTML>\r\n");
    if (num == 400) {
        strcpy(type, "400 Bad Request");
        strcpy(notice, "Bad Request.");
    }
    if (num == 403) {
        strcpy(type, "403 Forbidden");
        strcpy(notice, "Access denied.");
    }
    if (num == 404) {
        strcpy(type, "404 Not Found");
        strcpy(notice, "File not found.");
    }
    if (num == 500) {
        strcpy(type, "500 Internal Server Error");
        strcpy(notice, "Some server side error.");
    }
    if (num == 501) {
        strcpy(type, "501 Not supported");
        strcpy(notice, "Method is not supported.");
    }
    len = strlen(html) + (2 * strlen(type)) + strlen(notice);
    memset(buf, '\0', 512);
    sprintf(buf, "HTTP/1.0 %s\r\nContent-Type: text/html\nContent-Length: %zu\nConnection: close\r\n\r\n"
                 "<HTML><HEAD><TITLE>%s</TITLE></HEAD>\r\n<BODY><H4>%s</H4>\r\n%s\r\n</BODY></HTML>\r\n", type, len,
            type, type, notice);
}

/**
 * Sending a specific error to the socket.
 * @param errNum type of the error
 * @param sd socket descriptor
 * @param str1ToStr4 char* to free
 * @param url URL struct
 */
void sendError(int errNum, int sd, char *str1, char *str2, char *str3, char *str4, URL *url) {
    char handle[512];
    handleError(handle, errNum);
    write(sd, handle, strlen(handle));
    close(sd);
    if (str1 != NULL) free(str1);
    if (str2 != NULL) free(str2);
    if (str3 != NULL) free(str3);
    if (str4 != NULL) free(str4);
    if (url != NULL) free(url);
}

/**
 * Convert a file extension to mime type.
 * @param name the domain
 * @return the content-type
 */
char *get_mime_type(char *name) {
    char *ext = strrchr(name, '.');
    if (!ext) return NULL;
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".au") == 0) return "audio/basic";
    if (strcmp(ext, ".wav") == 0) return "audio/wav";
    if (strcmp(ext, ".avi") == 0) return "video/x-msvideo";
    if (strcmp(ext, ".mpeg") == 0 || strcmp(ext, ".mpg") == 0) return "video/mpeg";
    if (strcmp(ext, ".mp3") == 0) return "audio/mpeg";
    return NULL;
}

/**
 * Convert name to IP.
 * @param hostName the domain
 * @return IP address
 */
char *nameToAddress(char *hostName) {
    struct hostent *hp;
    struct in_addr address;
    char *ip;
    hp = gethostbyname(hostName);
    if (hp == NULL) {
        herror("failed: gethostbyname\n");
        exit(EXIT_FAILURE);
    }
    while (*hp->h_addr_list) {
        bcopy(*hp->h_addr_list++, (char *) &address, sizeof(address));
        ip = (char *) malloc(strlen(inet_ntoa(address)) + 1);
        if (ip == NULL)
            return NULL;
        memcpy(ip, inet_ntoa(address), strlen(inet_ntoa(address)));
        ip[strlen(inet_ntoa(address))] = '\0';
    }
    return ip;
}

/**
 * Checking if the address is in the filter file(only in IP list).
 * @param ip IP Link list
 * @param address the address to check
 * @return 0 - the address is legal, 1 - the address is illegal, -1 - if malloc failed
 */
int searchAddressInIpList(LinkList_IP *ip, char *address) {
    char *copy = (char *) malloc(strlen(address) + 1);
    if (copy == NULL)
        return -1;
    NodeIP *headIP = ip->first, *p;
    while (headIP != NULL) {
        p = headIP;
        headIP = headIP->next;
        memcpy(copy, address, strlen(address));
        copy[strlen(address)] = '\0';
        parseIp(copy, p->mask);
        if (strcmp(p->data, copy) == 0) {
            free(copy);
            return 1;
        }
    }
    free(copy);
    return 0;
}

/**
 * Checking if the address is in the filter file.
 * @param host Host Link list
 * @param ip IP Link list
 * @param address the address to check
 * @return 0 - the address is legal, 1 - the address is illegal, -1 - if malloc failed
 */
int searchAddressInFilter(LinkList_Host *host, LinkList_IP *ip, char *address) {
    int searchInIp;
    char *ipAdd;
    if (address[0] < 48 || address[0] > 57) {
        NodeHost *headHost = host->first, *p;
        while (headHost != NULL) {
            p = headHost;
            headHost = headHost->next;
            if (strcmp(p->data, address) == 0) {
                return 1;
            }
        }
        ipAdd = nameToAddress(address);
        if (ipAdd == NULL)
            return -1;
        searchInIp = searchAddressInIpList(ip, ipAdd);
        free(ipAdd);
        return searchInIp;
    }
    searchInIp = searchAddressInIpList(ip, address);
    return searchInIp;
}

/**
 * Open server to accept clients.
 * @param port the port that server listen to
 * @return sd, -1 if any syscall failure
 */
int openServer(int port) {
    int sd;
    struct sockaddr_in srv;
    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("error: socket\n");
        return -1;
    }
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    srv.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sd, (struct sockaddr *) &srv, sizeof(srv)) < 0) {
        perror("error: bind\n");
        return -1;
    }
    if (listen(sd, 5) < 0) {
        perror("error: listen\n");
        return -1;
    }
    return sd;
}

/**
 * Connect to the server.
 * @param hostName the domain.
 * @return fd of socket, -1 if failed
 */
int connectToServer(char *hostName) {
    int fd;
    struct sockaddr_in sd_socket;
    struct hostent *hp;
    sd_socket.sin_family = AF_INET;
    if (isdigit(hostName[0])) {
        struct in_addr address;
        inet_aton(hostName, &address);
        hp = gethostbyaddr(&address, sizeof(address), AF_INET);
    } else {
        hp = gethostbyname(hostName);
    }
    if (hp == NULL) {
        herror("failed: gethostbyname\n");
        exit(EXIT_FAILURE);
    }
    sd_socket.sin_addr.s_addr = ((struct in_addr *) (hp->h_addr))->s_addr;
    sd_socket.sin_port = htons(80);

    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("error: socket\n");
        return -1;
    }
    if (connect(fd, (struct sockaddr *) &sd_socket, sizeof(sd_socket)) < 0) {
        perror("error: connect\n");
        return -1;
    }
    return fd;
}

/**
 * Request analysis to check if it is valid for sending.
 * @param req the request to parsing
 * @param clientSd the socket
 * @param unFilter to know if we have filter, 0 - have, 1 - there is no
 * @param host_list Host Link list
 * @param ip_list IP Link list
 * @return struct URL, NULL if failed
 */
URL *parseRequest(char **req, int clientSd, int unFilter, LinkList_Host *host_list, LinkList_IP *ip_list) {
    URL *url;
    url = (URL *) calloc(1, sizeof(URL));
    if (url == NULL) {
        sendError(500, clientSd, NULL, NULL, NULL, NULL, NULL);
        return NULL;
    }
    char *copy = malloc(strlen(*req) + 1);
    if (copy == NULL) {
        sendError(500, clientSd, NULL, NULL, NULL, NULL, url);
        return NULL;
    }
    strcpy(copy, *req);
    copy[strlen(*req)] = '\0';
    char *get, *path, *protocol, *checkHost, *host;
    checkHost = strcasestr(copy, "host:");
    get = strtok(copy, " ");
    path = strtok(NULL, " ");
    protocol = strtok(NULL, " \r\n");
    int checkVersion = 0;
    if (protocol != NULL) {
        if ((strcmp(protocol, "HTTP/1.0") != 0) && (strcmp(protocol, "HTTP/1.1") != 0)) {
            checkVersion = 1;
        }
    }
    if (get == NULL || path == NULL || protocol == NULL || checkHost == NULL || checkVersion == 1) {
        sendError(400, clientSd, NULL, copy, NULL, NULL, url);
        return NULL;
    }
    if (strcmp(get, "GET") != 0) {
        sendError(501, clientSd, NULL, copy, NULL, NULL, url);
        return NULL;
    }
    host = strstr(checkHost, " ");
    if (host != NULL) {
        host = strtok(checkHost, " ");
        host = strtok(NULL, " \r\n");
    } else {
        host = strtok(checkHost, ":");
        host = strtok(NULL, " \r\n");
    }
    struct hostent *hp;
    if (isdigit(host[0])) {
        struct in_addr address;
        inet_aton(host, &address);
        hp = gethostbyaddr(&address, sizeof(address), AF_INET);
    } else {
        hp = gethostbyname(host);
    }
    if (hp == NULL) {
        sendError(404, clientSd, NULL, copy, NULL, NULL, url);
        return NULL;
    }
    if (unFilter == 0) {
        int checkAddress = searchAddressInFilter(host_list, ip_list, host);
        if (checkAddress == 1) {
            sendError(403, clientSd, NULL, copy, NULL, NULL, url);
            return NULL;
        }
        if (checkAddress == -1) {
            sendError(500, clientSd, NULL, copy, NULL, NULL, url);
            return NULL;
        }
    }
    char *page = "index.html";
    char *savePath = (char *) malloc(strlen(path) + 1);
    if (savePath == NULL) {
        sendError(500, clientSd, NULL, copy, NULL, NULL, url);
        return NULL;
    }
    memset(savePath, '\0', strlen(path) + 1);
    strcpy(savePath, path);
    if (savePath[strlen(savePath) - 1] == '/') {
        savePath = realloc(savePath, strlen(savePath) + strlen(page) + 1);
        if (savePath == NULL) {
            sendError(500, clientSd, NULL, copy, NULL, NULL, url);
            return NULL;
        }
        memset(savePath + strlen(savePath), '\0', strlen(page) + 1);
        strcat(savePath, page);
    }
    char *fullPath = (char *) malloc(strlen(savePath) + strlen(host) + 1);
    if (fullPath == NULL) {
        sendError(500, clientSd, NULL, copy, savePath, NULL, url);
        return NULL;
    }
    memset(fullPath, '\0', strlen(savePath) + strlen(host) + 1);
    strcat(fullPath, host);
    strcat(fullPath, savePath);

    char *saveHost = (char *) malloc(strlen(host) + 1);
    if (saveHost == NULL) {
        sendError(500, clientSd, NULL, copy, savePath, fullPath, url);
        return NULL;
    }
    memset(saveHost, '\0', strlen(host) + 1);
    strcpy(saveHost, host);

    char *tempReq = "GET  \r\nHOST: \r\nConnection: close\r\n\r\n";
    *req = realloc(*req, strlen(tempReq) + strlen(path) + strlen(protocol) + strlen(host) + 1);
    if (req == NULL) {
        sendError(500, clientSd, saveHost, copy, savePath, fullPath, url);
        return NULL;
    }
    sprintf(*req, "GET %s %s\r\nHOST: %s\r\nConnection: close\r\n\r\n", path, protocol, host);
    url->hostName = saveHost;
    url->path = savePath;
    url->fullPath = fullPath;
    free(copy);
    return url;
}

/**
 * Create folders.
 * @param url URL struct.
 * @return 0 - success, -1 - failed
 */
int createDirectory(URL *url) {
    char *cpyPath, *token, *temp, *slash;
    cpyPath = (char *) calloc(strlen(url->fullPath) + 1, sizeof(char));
    if (cpyPath == NULL)
        return -1;
    strcpy(cpyPath, url->fullPath);
    struct stat st = {0};
    slash = "/";
    int countSlash = 0, sizeMalloc = 0, j = 0;
    for (size_t i = 0; i < strlen(cpyPath); i++) {
        if (cpyPath[i] == '/') {
            countSlash++;
            sizeMalloc += j;
            j = 0;
        } else {
            j++;
        }
    }
    temp = (char *) calloc((sizeMalloc + countSlash), sizeof(char));
    if (temp == NULL)
        return -1;
    token = strtok(cpyPath, slash);
    strcat(temp, token);
    while (countSlash > 0) {
        if (stat(temp, &st) == -1) {
            if (mkdir(temp, 0700) == -1) {
                return -1;
            }
        }
        if (countSlash == 1)
            break;
        token = strtok(NULL, slash);
        strcat(temp, slash);
        strcat(temp, token);
        countSlash--;
    }
    free(temp);
    free(cpyPath);
    return 0;
}

/**
 * Send the file from file system to client.
 * @param fp file pointer(fopen).
 * @param url URL struct.
 * @param clientSd the client socket
 * @return 0 - success, -1 - failed
 */
int fromSystem(FILE *fp, URL *url, int clientSd) {
    size_t fileLen;
    size_t checkRead;
    if (fseek(fp, 0L, SEEK_END) != 0) {
        perror("error: fseek.\n");
        fclose(fp);
        return -1;
    }
    fileLen = (int) ftell(fp);
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("error: fseek.\n");
        fclose(fp);
        return -1;
    }
    char sizeFile[20];
    sprintf(sizeFile, "%zu", fileLen);
    char tempRes[LEN] = {'\0'};
    char *type = get_mime_type(url->path);
    int ex_type = 0;
    if (type != NULL) {
        strcpy(tempRes, "HTTP/1.0 200 OK\r\nContent-Length: \r\nContent-type: \r\nConnection: close\r\n\r\n");
        ex_type = (int) strlen(type);
    } else {
        strcpy(tempRes, "HTTP/1.0 200 OK\r\nContent-Length: \r\nConnection: close\r\n\r\n");
    }

    char *response = (char *) calloc(strlen(tempRes) + ex_type + strlen(sizeFile) + 1, sizeof(char));
    if (response == NULL) {
        fclose(fp);
        return -1;
    }
    sprintf(response, "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\n", fileLen);
    if (ex_type != 0) {
        strcat(response, "Content-type: ");
        sprintf(response + strlen(response), "%s\r\n", type);
    }
    strcat(response, "Connection: close\r\n\r\n");

    if (write(clientSd, response, strlen(response)) < 0) {
        fclose(fp);
        return -1;
    }
    u_char printFromFile[BUF_LEN + 1];
    memset(printFromFile, '\0', BUF_LEN + 1);
    checkRead = fread(printFromFile, 1, BUF_LEN, fp);
    if (ferror(fp)) {
        fprintf(stderr, "fread: failed.\n");
        fclose(fp);
        return -1;
    }
    size_t temp = checkRead;
    while (checkRead != fileLen) {
        if (write(clientSd, printFromFile, temp) < 0) {
            fclose(fp);
            return -1;
        }
        memset(printFromFile, '\0', BUF_LEN + 1);
        temp = fread(printFromFile, 1, BUF_LEN, fp);
        if (ferror(fp)) {
            fprintf(stderr, "fread: failed.\n");
            fclose(fp);
            return -1;
        }
        if (temp == 0)
            break;
        checkRead += temp;
    }
    if (write(clientSd, printFromFile, temp) < 0) {
        fclose(fp);
        return -1;
    }
    int totalLen = (int) (fileLen + strlen(sizeFile) + strlen(response));
    printf("File is given from local filesystem\n");
    printf("\n Total response bytes: %d\n", totalLen);
    free(response);
    return 0;
}

/**
 * Send the file from server to client socket and make a file.
 * @param url URL struct
 * @param req the request
 * @param clientSd the client socket
 * @return 0 - success, -1 - failed
 */
int fromServer(URL *url, char *req, int clientSd) {
    ssize_t checkRead, headCount = 0, checkReadBuf1, checkReadBuf2, sizeOfFile = 0, totalSize;
    int status;
    u_char buf1[BUF_LEN + 1], buf2[BUF_LEN + 1], buf12[(2 * BUF_LEN) + 1];
    memset(buf1, '\0', BUF_LEN + 1);
    memset(buf2, '\0', BUF_LEN + 1);
    memset(buf12, '\0', (2 * BUF_LEN) + 1);

    int sd = connectToServer(url->hostName);
    if (sd == -1)
        return -1;
    ssize_t sumWritten = 0, checkWrite = -1;
    while ((sumWritten != (ssize_t) strlen(req)) && (checkWrite != 0)) {
        if ((checkWrite = write(sd, req, strlen(req))) < 0) {
            close(sd);
            return -1;
        }
        sumWritten += checkWrite;
    }
    if ((checkReadBuf1 = read(sd, buf1, BUF_LEN)) < 0) {
        close(sd);
        return -1;
    }
    char *stat = strstr((char *) buf1, "1.");
    status = (int) strtol(stat + 4, NULL, 10);

    if ((checkReadBuf2 = read(sd, buf2, BUF_LEN)) < 0) {
        close(sd);
        return -1;
    }
    memcpy(buf12, buf1, checkReadBuf1);
    memcpy((buf12 + checkReadBuf1), buf2, checkReadBuf2);

    printf("HTTP request =\n%s\nLEN = %lu\n", req, strlen(req));
    while (strstr((char *) buf12, "\r\n\r\n") == NULL) { /// Separation between headers and body.
        if (write(clientSd, buf1, checkReadBuf1) < 0) {
            close(sd);
            return -1;
        }
        headCount += checkReadBuf1;
        strcpy((char *) buf1, (char *) buf2);
        checkReadBuf1 = checkReadBuf2;
        if ((checkReadBuf2 = read(sd, buf2, BUF_LEN)) < 0) {
            close(sd);
            return -1;
        }
        memset(buf12, '\0', (2 * BUF_LEN) + 1);
        memcpy(buf12, buf1, checkReadBuf1);
        memcpy((buf12 + checkReadBuf1), buf2, checkReadBuf2);
    }
    char *toFile = strstr((char *) buf12, "\r\n\r\n");
    toFile += 4;
    long printOut = toFile - (char *) buf12;
    headCount += printOut;
    if (write(clientSd, buf12, printOut) < 0) {
        close(sd);
        return -1;
    }
    int charsPrintToFile = ((int) (checkReadBuf1 + checkReadBuf2) - ((int) printOut));
    if (charsPrintToFile > 0) {
        if (write(clientSd, toFile, charsPrintToFile) < 0) {
            close(sd);
            return -1;
        }
        sizeOfFile += charsPrintToFile;
    }
    if (status >= 200 && status < 300) { /// Know if the requested website exists.
        int dir = createDirectory(url);
        if (dir == -1) {
            close(sd);
            return -1;
        }
        int fpp = open(url->fullPath, O_CREAT | O_WRONLY, 0644);
        if (fpp < 0) {
            perror("open: failed\n");
            close(sd);
            return -1;
        }
        if (charsPrintToFile > 0) {
            if (write(fpp, toFile, charsPrintToFile) < 0) {
                close(sd);
                close(fpp);
                return -1;
            }
        }
        memset(buf12, '\0', (2 * BUF_LEN) + 1);
        if ((checkRead = read(sd, buf12, (2 * BUF_LEN))) < 0) {
            close(sd);
            close(fpp);
            return -1;
        }
        while (checkRead != 0) {
            sizeOfFile += checkRead;
            if (write(fpp, buf12, checkRead) < 0) { /// Write tp file.
                close(sd);
                close(fpp);
                return -1;
            }
            if (write(clientSd, buf12, checkRead) < 0) { /// Write to screen.
                close(sd);
                close(fpp);
                return -1;
            }
            memset(buf12, '\0', (2 * BUF_LEN) + 1);
            if ((checkRead = read(sd, buf12, (2 * BUF_LEN))) < 0) {
                close(sd);
                close(fpp);
                return -1;
            }
        }
        close(fpp);
    } else { /// If url not found.
        if ((checkRead = read(sd, buf12, (2 * BUF_LEN))) < 0) {
            close(sd);
            return -1;
        }
        sizeOfFile += checkRead;
        while (checkRead != 0) {
            if (write(clientSd, buf12, checkRead) < 0) {
                close(sd);
                return -1;
            }
            memset(buf12, '\0', (2 * BUF_LEN) + 1);
            if ((checkRead = read(sd, buf12, (2 * BUF_LEN))) < 0) {
                close(sd);
                return -1;
            }
            sizeOfFile += checkRead;
        }
    }
    totalSize = (sizeOfFile + headCount);
    printf("File is given from origin server\n");
    printf("\n Total response bytes: %zu\n", totalSize);
    close(sd);
    return 0;
}

/**
 * The main function that the thread do.
 * @param arg struct with data
 * @return 0 - success, -1 - failed
 */
int threadWork(void *arg) {
    argThread *args = ((argThread *) arg);
    char *req = (char *) malloc(LEN + 1);
    if (req == NULL) {
        sendError(500, args->sd, NULL, NULL, NULL, NULL, NULL);
        return -1;
    }
    memset(req, '\0', LEN + 1);
    ssize_t nBytes, totalLenReq = 0;
    while ((nBytes = read(args->sd, req + totalLenReq, LEN)) > 0) {
        if (nBytes < 0) {
            sendError(500, args->sd, NULL, NULL, NULL, NULL, NULL);
            return -1;
        }
        if (strstr(req, "\r\n\r\n") != NULL)
            break;
        totalLenReq += nBytes;
        req = (char *) realloc(req, totalLenReq + LEN);
        if (req == NULL) {
            sendError(500, args->sd, NULL, NULL, NULL, NULL, NULL);
            return -1;
        }
        memset(req + totalLenReq, '\0', LEN);
    }
    URL *url;
    url = parseRequest(&req, args->sd, args->unFilter, args->host_list, args->ip_list);
    if (url == NULL) {
        free(req);
        return -1;
    }
    FILE *fp = fopen(url->fullPath, "r");
    int suc = 0;
    if (fp != NULL) { /// The file appears in the local filesystem.
        suc = fromSystem(fp, url, args->sd);
        fclose(fp);
    } else {
        suc = fromServer(url, req, args->sd);
    }
    if (suc == -1) {
        sendError(500, args->sd, req, url->hostName, url->path, url->fullPath, url);
        return -1;
    }
    free(req);
    free(url->hostName);
    free(url->path);
    free(url->fullPath);
    free(url);
    close(args->sd);
    return 0;
}

/**
 * Opening a server, creating threads to execute requests.
 * @param port the port that server listen to
 * @param poolSize the size of the threadpool
 * @param maxReq Top block for the number of requests
 * @param host_list Host Link list
 * @param ip_list IP Link list
 * @param unFilter to know if we have filter, 0 - have, 1 - there is no
 */
void server(int port, int poolSize, int maxReq, LinkList_Host *host_list, LinkList_IP *ip_list, int unFilter) {
    int countReq = 0, clientSd;
    threadpool *tp = create_threadpool(poolSize);
    if (tp == NULL) {
        free_LinkList(host_list, ip_list);
        exit(EXIT_FAILURE);
    }
    int sd = openServer(port);
    if (sd == -1) {
        free_LinkList(host_list, ip_list);
        exit(EXIT_FAILURE);
    }
    argThread **args = (argThread **) calloc(maxReq, sizeof(argThread *));
    if (args == NULL) {
        close(sd);
        free_LinkList(host_list, ip_list);
        exit(EXIT_FAILURE);
    }
    while (countReq < maxReq) {
        if ((clientSd = accept(sd, NULL, NULL)) < 0) {
            perror("error: accept\n");
            free_LinkList(host_list, ip_list);
            exit(EXIT_FAILURE);
        }
        args[countReq] = (argThread *) calloc(1, sizeof(argThread));
        if (args[countReq] == NULL) {
            sendError(500, clientSd, NULL, NULL, NULL, NULL, NULL);
        } else {
            args[countReq]->sd = clientSd;
            args[countReq]->unFilter = unFilter;
            args[countReq]->host_list = host_list;
            args[countReq]->ip_list = ip_list;
            dispatch(tp, threadWork, (void *) (args[countReq]));
        }
        countReq++;
    }
    destroy_threadpool(tp);
    for (int i = 0; i < maxReq; i++) {
        if (args[i] != NULL)
            free(args[i]);
    }
    free(args);
    close(sd);
}

/**
 * Check that the user entered valid arguments.
 * @param argc
 * @param argv
 * @return 0 - valid usage, -1 - invalid usage
 */
int validUsage(int argc, char **argv) {
    if (argc != 5)
        return -1;
    int val1, val2, val3;
    val1 = (int) strtol(argv[1], NULL, 10);
    val2 = (int) strtol(argv[2], NULL, 10);
    val3 = (int) strtol(argv[3], NULL, 10);
    if (val1 <= 0 || val2 <= 0 || val2 > MAXT_IN_POOL || val3 <= 0)
        return -1;
    return 0;
}

/**
 * @param argc
 * @param argv
 */
int main(int argc, char *argv[]) {
    int usage = validUsage(argc, argv), unFilter;
    if (usage == -1) {
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(EXIT_FAILURE);
    }
    LinkList_Host *host = NULL;
    LinkList_IP *ip = NULL;
    FILE *fp = fopen(argv[4], "r");
    if (fp == NULL) {
        fprintf(stderr, "fopen: failed");
        exit(EXIT_FAILURE);
    }
    unFilter = checkFilter(fp); ///return 1 if the filter is empty or if the file not exists.
    if (unFilter == 0) {
        host = (LinkList_Host *) malloc(sizeof(LinkList_Host));
        ip = (LinkList_IP *) malloc(sizeof(LinkList_IP));
        initLists(host, ip, fp);
        makeFilter(fp, host, ip);
    }
    int port, poolSize, maxReq;
    port = (int) strtol(argv[1], NULL, 10);
    poolSize = (int) strtol(argv[2], NULL, 10);
    maxReq = (int) strtol(argv[3], NULL, 10);
    server(port, poolSize, maxReq, host, ip, unFilter);
    free_LinkList(host, ip);
    return 0;
}
