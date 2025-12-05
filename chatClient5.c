#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"

static int handle_io_failure(SSL *ssl, int res)
{
    switch (SSL_get_error(ssl, res)) {
    case SSL_ERROR_WANT_READ:
        /* Temporary failure. Wait until we can read and try again */
        return 1;

    case SSL_ERROR_WANT_WRITE:
        /* Temporary failure. Wait until we can write and try again */
        return 1;

    case SSL_ERROR_ZERO_RETURN:
        /* EOF */
        return 0;

    case SSL_ERROR_SYSCALL:
        return -1;

    /*
    case SSL_ERROR_SSL:
        /*
        * If the failure is due to a verification error we can get more
        * information about it from SSL_get_verify_result().
        
        if (SSL_get_verify_result(ssl) != X509_V_OK)
            printf("Verify error: %s\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
    */

    default:
        return -1;
    }
}

int main()
{
	int				sockfd, dir_sockfd;
	struct sockaddr_in chat_serv_addr, dir_serv_addr;
	fd_set			readset, writeset;
  char ip_address[100];
  char chat_server_selection[MAX];
  int port = 0;
  int ret;

  //Create SSL_CTX object
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if(ctx == NULL)
  {
    perror("client: Failed to create the SSL_CTX");
    exit(1);
  }

  SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);

  //Configure to include certificate verification
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  if(!SSL_CTX_set_default_verify_paths(ctx))
  {
    perror("client: Couldn't set default certificate store");
    exit(1);
  }

  //Ensure minimum TLS version
  if(!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION))
  {
    perror("client: Failed to set minimum TLS version");
    exit(1);
  }

  SSL_CTX_load_verify_locations(ctx, "noPassRootCA.crt", NULL);

  //Create SSL object for directory
  SSL* directory_ssl = SSL_new(ctx);
  if(directory_ssl == NULL)
  {
    perror("client: Failed to create SSL object");
    exit(1);
  }


	/* Set up the address of the directory server. */
	memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family			= AF_INET;
	dir_serv_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	dir_serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Create a socket (an endpoint for communication). */
	if ((dir_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(dir_sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
    if (errno != EINPROGRESS) {
      perror("client: can't connect to directory server");
      return EXIT_FAILURE;
    }
	}

  //Make the socket nonblocking
  if (0 != fcntl(dir_sockfd, F_SETFL, O_NONBLOCK)) {
    perror("server: couldn't set directory socket to nonblocking");
    close(dir_sockfd);
    exit(1);
  }

  BIO *bio;
  //Create a BIO object
  bio = BIO_new(BIO_s_socket());
  if(bio == NULL)
  {
    BIO_closesocket(dir_sockfd);
    exit(1);
  }

  //Wrap socket with BIO object
  BIO_set_fd(bio, dir_sockfd, BIO_CLOSE);

  //Associate the SSL object with the BIO object
  SSL_set_bio(directory_ssl, bio, bio);

  if(!SSL_set_tlsext_host_name(directory_ssl, "Directory Server"))
  {
    perror("client: Failed to set SNI hostname");
    exit(1);
  }

  if(!SSL_set1_host(directory_ssl, "Directory Server"))
  {
    perror("client: Failed to set certificate verification hostname");
    exit(1);
  }

  while ((ret = SSL_connect(directory_ssl)) != 1)
  {
    if (handle_io_failure(directory_ssl, ret) == 1)
      continue;
    printf("Failed to connect to server\n");
    exit(1);
  }

	/* Your directory server logic here... */ 
  char s_d[MAX] = {'\0'}; 
  char s_d1[MAX * 10] = {'\0'}; 
  FD_ZERO(&readset); 
  FD_SET(STDIN_FILENO, &readset); 
  FD_SET(dir_sockfd, &readset); 
  if(select(dir_sockfd+1, &readset, NULL, NULL, NULL) > 0) { 
    snprintf(s_d, MAX, "c"); 
    while(!SSL_write(directory_ssl, s_d, MAX))
    {
      if (handle_io_failure(directory_ssl, 0) == 1)
        continue; /* Retry */
      fprintf(stderr, "%s:%d Error writing to directory server\n", __FILE__, __LINE__); //DEBUG
      SSL_free(directory_ssl);
      SSL_CTX_free(ctx);
      exit(1);
    }

    for(;;) //read until server response 
    { 
      FD_ZERO(&readset); 
      FD_SET(STDIN_FILENO, &readset); 
      FD_SET(dir_sockfd, &readset);
      if(select(dir_sockfd+1, &readset, NULL, NULL, NULL) > 0) 
      { 
        if (FD_ISSET(dir_sockfd, &readset)) 
        { 
          ssize_t nread = SSL_read(directory_ssl, s_d1, MAX);
          if (nread <= 0) 
          { 
            /* Not every error is fatal. Check the return value and act accordingly. */
            switch (handle_io_failure(directory_ssl, nread)) {
              case 1:
                break;
              case 0:
                perror("Error: Connection closed by directory");
                SSL_free(directory_ssl);
                SSL_CTX_free(ctx);
                exit(1);
              case -1:
                fprintf(stderr, "This system error\n");
                perror("Error: System error");
                SSL_free(directory_ssl);
                SSL_CTX_free(ctx);
                exit(1);
              default:
                printf("Failed reading remaining data\n");
                exit(1);
            }
          } 
          else 
          {
            s_d1[nread] = '\0'; 
            fprintf(stderr, "%s\n",s_d1); 
            if(strncmp(s_d1, "Chat directory:\n", MAX * 10) != 0) //read until we see "Chat directory:"
            { 
              break; 
            } 
          } 
          
        } 
      } 
    }
    //Read all online chats
    if(strncmp(s_d1, "No chats online", MAX * 10) != 0) 
    {
      int server_count = -1;
      char server_info[MAX * 2];
      const char *cur = s_d1;
      char server_names[MAX][MAX];
      char name[MAX] = {'\0'};
      //determine server count
      while(sscanf(cur, "%199[^\n]\n", server_info) == 1)
      {
        int id;
        if(sscanf(server_info, "%d. Name: %99[^,]", &id, name) == 2)
        {
          int len = strnlen(name, MAX);
          snprintf(server_names[id], MAX, "%s", name);
          server_names[id][len-1] = '\0';
          server_names[id][MAX - 1] = '\0';
          server_count = id;
        }
        cur += strnlen(server_info, MAX * 2);
        while(*cur == '\n')
        {
          cur++;
        }
      }
      
      int loop = 1;
      while(loop == 1)
      {
        int index = -1;
        char s_d2[MAX] = {'\0'};
        if(1 == scanf(" %d", &index))
        {
          if(index >= 0 && index <= server_count)
          {
            //select server to join
            snprintf(s_d2, MAX, "c%s\n", server_names[index]);
            snprintf(chat_server_selection, MAX, "%s", server_names[index]);
            
            while(!SSL_write(directory_ssl, s_d2, MAX))
            {
              loop = 1;
              if (handle_io_failure(directory_ssl, 0) == 1)
                continue; /* Retry */
              fprintf(stderr, "%s:%d Error writing to directory server\n", __FILE__, __LINE__); //DEBUG
              SSL_free(directory_ssl);
              SSL_CTX_free(ctx);
              exit(1);
            }
            loop = 0;
          }
          else 
          {
            fprintf(stderr,"\nPlease enter a valid index\n");
            loop = 1;
          }
        }
        else
        {
          scanf(" %99[^\t\n]", s_d2);
        }
      }
      
      char s_d3[MAX] = {'\0'};
      
      for(;;) //read until server response
      {
        if(select(dir_sockfd+1, &readset, NULL, NULL, NULL) > 0)
        {
          if (FD_ISSET(dir_sockfd, &readset)) 
          {
            ssize_t nread = SSL_read(directory_ssl, s_d3, MAX);
            if(nread <= 0) 
            {
              /* Not every error is fatal. Check the return value and act accordingly. */
              switch (handle_io_failure(directory_ssl, nread)) {
                case 1:
                  continue;
                case 0:
                  perror("Error: Connection closed by directory");
                  SSL_free(directory_ssl);
                  SSL_CTX_free(ctx);
                  exit(1);
                case -1:
                  perror("Error: System error");
                  SSL_free(directory_ssl);
                  SSL_CTX_free(ctx);
                  exit(1);
                default:
                  printf("Failed reading remaining data\n");
                  exit(1);
              }
              fprintf(stderr, "%s:%d Error reading from directory server\n", __FILE__, __LINE__); //DEBUG
            } 
            else 
            {
              if(strncmp(s_d3, "fail", 4) == 0)
              {
                fprintf(stderr, "Server not found");
                exit(1);
              }
              if(sscanf(s_d3, "%99s %d", ip_address, &port) == 2)
              {
                printf("Connecting to chat server...\n");
                break;
              }
              else
              {
                fprintf(stderr, "%s:%d Error parsing directory server messages\n", __FILE__, __LINE__); //DEBUG
              }
            }
          }
        }
      }
    }
    else
    {
      fprintf(stderr,"Please try again later!\n");
      exit(1);
    }
  } 
  else 
  { 
    exit(0); 
    //failed to connect to directory server 
  }

   //Create SSL object for directory
  SSL* chat_ssl = SSL_new(ctx);
  if(chat_ssl == NULL)
  {
    perror("client: Failed to create SSL object");
    exit(1);
  }
  
	/* Set up the address of the chat server. */
	memset((char *) &chat_serv_addr, 0, sizeof(chat_serv_addr));
	chat_serv_addr.sin_family			= AF_INET;
	chat_serv_addr.sin_addr.s_addr	= inet_addr(ip_address);;
	chat_serv_addr.sin_port				= htons(port);	

	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Connect to the server. */
	if (connect(sockfd, (struct sockaddr *) &chat_serv_addr, sizeof(chat_serv_addr)) < 0) {
		perror("client: can't connect to server");
		return EXIT_FAILURE;
	}

    //Make the socket nonblocking
  if (0 != fcntl(sockfd, F_SETFL, O_NONBLOCK)) {
    perror("server: couldn't set socket to nonblocking");
    close(sockfd);
    exit(1);
  }

  
  BIO *bio_chat;
  //Create a BIO object
  bio_chat = BIO_new(BIO_s_socket());
  if(bio_chat == NULL)
  {
    BIO_closesocket(sockfd);
    exit(1);
  }

  //Wrap socket with BIO object
  BIO_set_fd(bio_chat, sockfd, BIO_CLOSE);

  //Associate the SSL object with the BIO object
  SSL_set_bio(chat_ssl, bio_chat, bio_chat);

  if(!SSL_set_tlsext_host_name(chat_ssl, chat_server_selection))
  {
    perror("client: Failed to set SNI hostname");
    exit(1);
  }

  if(!SSL_set1_host(chat_ssl, chat_server_selection))
  {
    perror("client: Failed to set certificate verification hostname");
    exit(1);
  }
  /* Do the handshake with the server */
  while ((ret = SSL_connect(chat_ssl)) != 1)
  {
    if (handle_io_failure(chat_ssl, ret) == 1)
      continue;
    printf("Failed to connect to server\n");
    exit(1);
  }

  char writeBuf[MAX];
  snprintf(writeBuf, MAX, '\0');
	for(;;) {

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);
    if (strnlen(writeBuf, MAX) > 0){
		  FD_SET(sockfd, &writeset);
    }

		if (select(sockfd+1, &readset, &writeset, NULL, NULL) > 0)
		{
			char s[MAX] = {'\0'};

			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				if (1 == scanf(" %100[^\t\n]", s)) { /* reads until there is a tab or new line and up to 100 characters */
					/* Send the user's message to the server */
          snprintf(writeBuf, MAX, "%s", s);
				} else {
					fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__); //DEBUG
				}
			}

      if (FD_ISSET(sockfd, &writeset)){
        ssize_t nwrite = SSL_write(chat_ssl, writeBuf, MAX);

        if(nwrite <= 0)
        {
          if (handle_io_failure(chat_ssl, 0) != 1)
          {
            fprintf(stderr, "%s:%d Error writing to directory server\n", __FILE__, __LINE__); //DEBUG
            SSL_free(directory_ssl);
            SSL_free(chat_ssl);
            SSL_CTX_free(ctx);
            exit(1);
          }
        }
        else
        {
          snprintf(writeBuf, MAX, '\0');
        }

        /* Following lines cited from https://en.wikipedia.org/wiki/ANSI_escape_code#Fe_Escape_sequences 
        Deletes the current "Enter message: " string when typing in a chat message */
        fprintf(stderr, "\x1b[1F"); //Move cursor to previous line
        fprintf(stderr, "\x1b[2K"); //Delete content on this line
      }

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
        ssize_t nread = SSL_read(chat_ssl, s, MAX);
        if (nread <= 0) {
          /* Not every error is fatal. Check the return value and act accordingly. */
          switch (handle_io_failure(chat_ssl, nread)) {
            case 1:
              continue;
            case 0:
              perror("Error: Connection closed by directory");
              SSL_free(directory_ssl);
              SSL_free(chat_ssl);
              SSL_CTX_free(ctx);
              exit(1);
            case -1:
              perror("Error: System error");
              SSL_free(directory_ssl);
              SSL_free(chat_ssl);
              SSL_CTX_free(ctx);
              exit(1);
            default:
              printf("Failed reading remaining data\n");
              exit(1);
            }
            fprintf(stderr, "%s:%d Error reading from chat server\n", __FILE__, __LINE__); //DEBUG
        } else {
          /* Also found from https://en.wikipedia.org/wiki/ANSI_escape_code#Fe_Escape_sequences 
          Removes "Enter message: " string and resets cursor when recieving data based on another client's input */
          fprintf(stderr, "\x1b[2K\r%s", s);
        }
			}
		}
	}
  SSL_free(directory_ssl);
  SSL_free(chat_ssl);
  SSL_CTX_free(ctx);
	// return or exit(0) is implied; no need to do anything because main() ends
}
