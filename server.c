#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <errno.h>
#include <pthread.h>

#define SVPORT 8008
#define CLPORT 8009

void HashASCII512(const char *message, unsigned char md[SHA512_DIGEST_LENGTH])
{
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, message, strlen(message));
    SHA512_Final(md, &ctx);
}

void *sendMessage(void *sock)
{
    int sockfd = *(int *)sock;

    char *message;
    char *hashInHex;
    char *messageCopy;
    char secret[] = "12923827";
    char separator[] = "<SEP>";
    unsigned char hash[SHA512_DIGEST_LENGTH];
    int messageSize = 2048;

    message = malloc(messageSize + sizeof(secret) + SHA512_DIGEST_LENGTH * 2 + 1);
    hashInHex = malloc(SHA512_DIGEST_LENGTH * 2 + 1);//Multiply by 2 because the hash is stored in hex format which takes up double the space.
    messageCopy = malloc(messageSize + sizeof(secret) + SHA512_DIGEST_LENGTH * 2 + 1);

    if(!message || !hashInHex)
    {
        perror("Failed to allocate memory allocate memory\n");
        exit(0);
    }

    while(1)
    {
        memset(message, 0, messageSize + sizeof(secret) + SHA512_DIGEST_LENGTH * 2 + 1);
        memset(hashInHex, 0, (SHA512_DIGEST_LENGTH * 2 + 1) - 1);
        memset(hash, 0, SHA512_DIGEST_LENGTH);
        memset(messageCopy, 0, messageSize + sizeof(secret) + SHA512_DIGEST_LENGTH * 2 + 1);

        printf("Enter the message: ");
        printf("\n");
        if(fgets(message, messageSize, stdin) == NULL)
        {
            perror("Failed to read input\n");
            free(message);
            free(messageCopy);
            free(hashInHex);
            break;
        }

        message[strcspn(message, "\n")] = '\0';
        printf("Message: %s\n", message);

        strncat(messageCopy, message, strlen(message));

        strcat(messageCopy, secret);
        printf("Key: %s\n", secret);

        printf("MessageCopy: %s\n", messageCopy);
        HashASCII512(messageCopy, hash);

        printf("Hash: ");
        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        {
            printf("%02x", hash[i]);
        }
        printf("\n");

        //converts int hash to hex string
        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        {
            sprintf(hashInHex + i * 2, "%02x", hash[i]);
        }

        strncat(message, separator, strlen(separator));
        strncat(message, hashInHex, SHA512_DIGEST_LENGTH * 2);
        printf("Final message with hash: %s\n", message);

        send(sockfd, message, strlen(message), 0);
        printf("Message sent\n");
    }
    
    free(message);
    free(messageCopy);
    free(hashInHex);
    return NULL;
}

void *recvMessage(void *sock)
{
    int sockfd = *(int *)sock;

    char *recvBuffer = malloc(2186);
    char secret[] = "12923827";
    int n;
    
    int hashLen = SHA512_DIGEST_LENGTH * 2 + 1;
    char *messageOut;
    char *hashOut;
    unsigned char newMessageHash[SHA512_DIGEST_LENGTH];
    char *newMessageHashInHex = malloc(SHA512_DIGEST_LENGTH * 2 + 1);

    recieve:
    while((n = recv(sockfd, recvBuffer, 2186, 0)) > 0)
    {
        recvBuffer[n] = '\0';
        printf("Recieved message with hash: %s\n", recvBuffer);
        
        const char *separatorLocation = strstr(recvBuffer, "<SEP>");
        if(separatorLocation == NULL)
        {
            fprintf(stderr, "Separator not found. Waiting for another message.\n");
            goto recieve;
        }

        ptrdiff_t messageLen = separatorLocation - recvBuffer;
        
        messageOut = malloc(messageLen + strlen(secret) + 1);
        strncpy(messageOut, recvBuffer, messageLen);
        messageOut[messageLen + strlen(secret)] = '\0';
        printf("Received message: %s\n", messageOut);

        const char *hashStart = separatorLocation + strlen("<SEP>");
        int hashLen = strlen(hashStart);

        hashOut = malloc(hashLen + 1);
        strcpy(hashOut, hashStart);
        hashOut[SHA512_DIGEST_LENGTH * 2 + 1] = '\0';
        printf("Received hash: %s\n", hashOut);

        strncat(messageOut, secret, strlen(secret));
        printf("Hashed: %s\n", messageOut);
        HashASCII512(messageOut, newMessageHash);

        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        {
            sprintf(newMessageHashInHex + i * 2, "%02x", newMessageHash[i]);
        }
        printf("New calculated hash: %s\n", newMessageHashInHex);

        if(strcmp(hashOut, newMessageHashInHex) == 0)
        {
            printf("The message and hash value match.\n");
        }
        else
        {
            printf("Hash values are different. The message is not secure\n");            
        }

        free(messageOut);
        free(hashOut);
        printf("Enter the message: \n");
    }
    free(recvBuffer);
    free(newMessageHashInHex);

    return NULL;
}

int main()
{
    int sockfd, connfd;
    struct sockaddr_in serverInfo, clientInfo;
    int optVal = 1;
    char machineIP[] = "127.0.0.1";
    int serverPort = SVPORT;
    int clientPort = CLPORT;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1)
    {
        perror("Socket creation failed\n");
        exit(0);
    }

    memset(&clientInfo, 0, sizeof(clientInfo));
    clientInfo.sin_family = AF_INET;
    clientInfo.sin_port = htons(clientPort);
    clientInfo.sin_addr.s_addr = inet_addr(machineIP);

    //tries to connect to peer machine. if connection fails, assumes server role.
    if(connect(sockfd, (struct sockaddr *) &clientInfo, sizeof(clientInfo)) == -1)
    {
        printf("Failed to connect to peer. This may be because peer is not listening.\n");
        printf("Converting to server mode\n");
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);

        //setup sockets again
        memset(&sockfd, 0, sizeof(sockfd));
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) < 0)
        {
            printf("Error setting socket options\n");
        }

        memset(&serverInfo, 0, sizeof(serverInfo));
        serverInfo.sin_family = AF_INET;
        serverInfo.sin_port = htons(serverPort);
        serverInfo.sin_addr.s_addr = inet_addr(machineIP);
        
        int bindRes = bind(sockfd, (struct sockaddr *) &serverInfo, sizeof(serverInfo));
        if(bindRes != 0)
        {
            printf("Error at bind: %s (%d)\n", strerror(errno), errno);
        }
        int listenRes = listen(sockfd, 5);
        if(listenRes != 0)
        {
            printf("Error at listen: %s (%d)\n", strerror(errno), errno);
        }

        socklen_t cli_len = sizeof(clientInfo);
        connfd = accept(sockfd, (struct sockaddr *) &clientInfo, &cli_len);
        sockfd = connfd;
    }
    else
    {
        printf("Connected to peer: %d\n", inet_ntoa(clientInfo.sin_addr));
    }

    pthread_t sendThread, recvThread;
    pthread_create(&sendThread, NULL, sendMessage, &sockfd);
    pthread_create(&recvThread, NULL, recvMessage, &sockfd);

    pthread_join(sendThread, NULL);
    pthread_join(recvThread, NULL);

    close(sockfd);

    return 0;
}