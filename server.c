/*
    Compile with gcc server.c -o server -lcrypto
    OPENSSL Libraries required 
    Compile official openssl libraries and install openssl headers using your linux distros pkg manager
    Run the included binary, using ./server secretfile 127.0.0.1
    The secretfile needs to contain a 256 bit key generated by openssl in hex format
*/

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

typedef struct sockdata
{
    int sockfd;
    char *secret;
} sockdata;

void HashASCII512(const char *message, unsigned char md[SHA512_DIGEST_LENGTH])
{
    //Keeps track of the number of rounds hash has been computed
    //Keeps track of the number of bits processed
    //Stores the message digest and hash value
    SHA512_CTX ctx;
    //Resets the count of the number of rounds
    //Resets the 64 bit counter for the total length of input. Counter used in the final calculation of the hash  
    SHA512_Init(&ctx);
    //Processes the incoming chunks of data
    //Updates the CTX with new data after each round until all the data is processed 
    //Data stored in a variable in the ctx and when filled, the 128 bit block is processed.
    SHA512_Update(&ctx, message, strlen(message));
    //Pads the final block of data if the full blocks are full and the final block is not 128 bits
    SHA512_Final(md, &ctx);
}

void *sendMessage(void *args)
{   
    //Initialises information used during sending process
    sockdata *sd = (sockdata *)args;

    //sockfd and secret values from main function used here
    int sockfd = sd->sockfd;
    char *message;
    char *hashInHex;
    char *messageCopy;
    char *secret = sd->secret;
    char separator[] = "<SEP>";
    unsigned char hash[SHA512_DIGEST_LENGTH];
    int messageSize = 2048;

    message = malloc(messageSize + sizeof(secret) + SHA512_DIGEST_LENGTH * 2 + 1);
    hashInHex = malloc(SHA512_DIGEST_LENGTH * 2 + 1);
    messageCopy = malloc(messageSize + sizeof(secret) + SHA512_DIGEST_LENGTH * 2 + 1);

    if(!message || !hashInHex)
    {
        perror("Failed to allocate memory\n");
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
        printf("Message: %s\n\n", message);

        //Makes a copy of the message and appends Secret to the copy
        strncat(messageCopy, message, strlen(message));
        strcat(messageCopy, secret);
        printf("Message and Key: %s\n\n", messageCopy);

        //Copy of message is hashed
        HashASCII512(messageCopy, hash);

        printf("Hash: ");
        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        {
            printf("%02x", hash[i]);
        }
        printf("\n\n");

        //Converts hash to hex
        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        {
            sprintf(hashInHex + i * 2, "%02x", hash[i]);
        }

        //Adds seperator to original message then appends hex to message
        strncat(message, separator, strlen("<SEP>"));
        strncat(message, hashInHex, strlen(hashInHex));
        printf("Final message with hash: %s\n\n", message);

        //Sends final message
        send(sockfd, message, strlen(message), 0);
        printf("Message sent\n\n");
    }
    
    free(message);
    free(messageCopy);
    free(hashInHex);
    return NULL;
}

void *recvMessage(void *args)
{
    sockdata *sd = (sockdata *)args;

    int sockfd = sd->sockfd;
    char *recvBuffer = malloc(2186);
    char *secret = sd->secret;
    int n;
    
    int hashLen = SHA512_DIGEST_LENGTH * 2 + 1;
    char *messageOut;
    char *hashOut;
    unsigned char newMessageHash[SHA512_DIGEST_LENGTH];
    char *newMessageHashInHex = malloc(SHA512_DIGEST_LENGTH * 2 + 1);
    
    //recv() is a blocking function
    while((n = recv(sockfd, recvBuffer, 2186, 0)) > 0)
    {   
        recvBuffer[n] = '\0';
        
        //Locates the separator in the String received
        const char *separatorLocation = strstr(recvBuffer, "<SEP>");
        if(separatorLocation == NULL)
        {
            fprintf(stderr, "Separator not found. Waiting for another message.\n");
            continue;
        }

        //Finds the length of message and splits message from the entire String 
        ptrdiff_t messageLen = separatorLocation - recvBuffer;
        messageOut = malloc(messageLen + strlen(secret) + 1);
        memset(messageOut, 0, messageLen + strlen(secret) + 1);
        strncpy(messageOut, recvBuffer, messageLen);
        messageOut[messageLen + strlen(secret)] = '\0';
        printf("Received message: %s\n\n", messageOut);

        //Finds the starting location and length of hash and splits it from the entire String
        const char *hashStart = separatorLocation + strlen("<SEP>");
        int hashLen = strlen(hashStart);
        hashOut = malloc(hashLen + 1);
        strcpy(hashOut, hashStart);
        hashOut[SHA512_DIGEST_LENGTH * 2 + 1] = '\0';
        printf("Received hash: %s\n\n", hashOut);

        //Appends the secret to the split message and computes its hash
        strcat(messageOut, secret);
        printf("Hashed: %s\n\n", messageOut);
        HashASCII512(messageOut, newMessageHash);

        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
        {
            sprintf(newMessageHashInHex + i * 2, "%02x", newMessageHash[i]);
        }
        printf("New calculated hash: %s\n\n", newMessageHashInHex);

        //Compares the hash received with the newly computed hash
        if(strcmp(hashOut, newMessageHashInHex) == 0)
        {
            printf("The message and hash value match.\n\n");
        }
        else
        {
            printf("Hash values are different. The message is not secure\n");            
        }

        memset(recvBuffer, 0, strlen(recvBuffer));
        free(messageOut);
        free(hashOut);
        printf("Enter the message: \n");
    }
    free(recvBuffer);
    free(newMessageHashInHex);

    return NULL;
}

int main(int argc, char *argv[])
{
    //Application takes in 2 input fields when running in the terminal. {APPNAME} {KEY FILE} {IP ADDR OF PEER}
    if(argc != 3)
    {
        fprintf(stderr, "Usage: %s [filepath] [ip addr]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    //Attempts to open SECRET FILE from file location input by user
    const char *filePath = argv[1];
    FILE *fp = fopen(filePath, "r");
    if(fp == NULL)
    {
        perror("Failed to open file. This could be because file does not exist or is an invalid format.\nAccepted format is only .txt. Other formats may work.\n");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    //Reads SECRET FILE and loads KEY
    char secret[513];
    if(fgets(secret, sizeof(secret), fp) == NULL)
    {
        fprintf(stderr, "Failed to read key from file.\n");
        fclose(fp);
        exit(EXIT_FAILURE);
    } 
    fclose(fp);
    secret[513 - 1] = '\0'; 

    //Prepares information to create network sockets
    int sockfd, connfd;
    struct sockaddr_in serverInfo, clientInfo;
    int optVal = 1;
    char *machineIP = argv[2];//Machine IP set to IP ADDR OF PEER input by user
    int serverPort = SVPORT;
    int clientPort = CLPORT;
    
    //Creates socket and sets socket params
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1)
    {
        perror("Socket creation failed\n");
        exit(0);
    }

    //Sets the informtion about peer machine
    memset(&clientInfo, 0, sizeof(clientInfo));
    clientInfo.sin_family = AF_INET;
    clientInfo.sin_port = htons(clientPort);
    clientInfo.sin_addr.s_addr = inet_addr(machineIP);

    //Tries to connect to peer machine. if connection fails, assumes server role.
    if(connect(sockfd, (struct sockaddr *) &clientInfo, sizeof(clientInfo)) == -1)
    {
        printf("Failed to connect to peer. This may be because peer is not listening.\n");
        printf("Converting to server mode\n");
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);

        //Sets sockets up again
        //sockfd contains information about the socket just created
        memset(&sockfd, 0, sizeof(sockfd));
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) < 0)
        {
            printf("Error setting socket options\n");
        }

        //Information about this machine
        memset(&serverInfo, 0, sizeof(serverInfo));
        serverInfo.sin_family = AF_INET;
        serverInfo.sin_port = htons(serverPort);
        serverInfo.sin_addr.s_addr = inet_addr(machineIP);
        
        //Binds socket to the IP and PORT
        int bindRes = bind(sockfd, (struct sockaddr *) &serverInfo, sizeof(serverInfo));
        if(bindRes != 0)
        {
            printf("Error at bind: %s (%d)\n", strerror(errno), errno);
        }

        //Sets Server to listening mode with 5 backlog
        int listenRes = listen(sockfd, 5);
        if(listenRes != 0)
        {
            printf("Error at listen: %s (%d)\n", strerror(errno), errno);
        }

        //Detects a connection request and accepts the request
        socklen_t cliLen = sizeof(clientInfo);
        connfd = accept(sockfd, (struct sockaddr *) &clientInfo, &cliLen);
        sockfd = connfd;
    }
    else
    {
        printf("Connected to peer: %d\n", inet_ntoa(clientInfo.sin_addr));
    }

    //sockdata is a struct 
    //sockdata passes in the secret and sockfd to the threads
    sockdata sd;
    sd.secret = secret;
    sd.sockfd = sockfd;
    
    //By default application runs on one thread.
    //The recv() socket function is a blocking function so to send and receive messages simulatniously, 
    //Send function is run on one thread and Recv function is run on another thread.
    //Simply creates 2 threads
    pthread_t sendThread, recvThread;
    pthread_create(&sendThread, NULL, sendMessage, &sd);
    pthread_create(&recvThread, NULL, recvMessage, &sd);

    //Executes threads
    pthread_join(sendThread, NULL);
    pthread_join(recvThread, NULL);

    close(sockfd);
    free(machineIP); 
    return 0;
}