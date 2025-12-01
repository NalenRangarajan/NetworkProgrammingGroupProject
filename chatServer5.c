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

int main()
{
	int				sockfd, dir_sockfd;
	struct sockaddr_in chat_serv_addr, dir_serv_addr;
	fd_set			readset;
  char ip_address[100];
  char chat_server_selection[MAX];
  int port = 0;

  //Create SSL_CTX object
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if(ctx == NULL)
  {
    perror("client: Failed to create the SSL_CTX");
    return;
  }

  SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);

  //Configure to include certificate verification
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  if(!SSL_CTX_set_default_verify_paths(ctx))
  {
    perror("client: Couldn't set default certificate store");
    return;
  }

  //Ensure minimum TLS version
  if(!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION))
  {
    perror("client: Failed to set minimum TLS version");
    return;
  }

  SSL_CTX_load_verify_locations(ctx, "noPassRootCA.crt", NULL);

  //Create SSL object for directory
  SSL* directory_ssl = SSL_new(ctx);
  if(directory_ssl == NULL)
  {
    perror("client: Failed to create SSL object");
    return;
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
		perror("client: can't connect to directory server");
		return EXIT_FAILURE;
	}

  BIO *bio;
  //Create a BIO object
  bio = BIO_new(BIO_s_socket());
  if(bio == NULL)
  {
    BIO_closesocket(dir_sockfd);
    return;
  }

  //Wrap socket with BIO object
  BIO_set_fd(bio, dir_sockfd, BIO_CLOSE);

  //Associate the SSL object with the BIO object
  SSL_set_bio(directory_ssl, bio, bio);

  if(!SSL_set_tlsext_host_name(directory_ssl, "Directory Server"))
  {
    perror("client: Failed to set SNI hostname");
    return;
  }

  if(!SSL_set1_host(directory_ssl, "Directory Server"))
  {
    perror("client: Failed to set certificate verification hostname");
    return;
  }

  if(SSL_connect(directory_ssl) < 1)
  {
    perror("client: Failed to connect to server");

    if(SSL_get_verify_result(directory_ssl) != X509_V_OK)
    {
      fprintf(stderr, "Verify error: %s\n", X509_verify_cert_error_string(SSL_get_verify_result(directory_ssl)));
    }
    return;
  }

	/* Your directory server logic here... */ 
  char s_d[MAX] = {'\0'}; 
  char s_d1[MAX * 10] = {'\0'}; 
  FD_ZERO(&readset); 
  FD_SET(STDIN_FILENO, &readset); 
  FD_SET(dir_sockfd, &readset); 
  if(select(dir_sockfd+1, &readset, NULL, NULL, NULL) > 0) { 
    int n = snprintf(s_d, MAX, "c\0"); 
    fprintf(stderr, "hit this");
    ssize_t nwrite = SSL_write(directory_ssl, s_d, n); //Write just 'c' to the directory server
    fprintf(stderr, "hit %d", nwrite);
    if(nwrite <= 0) { 
      fprintf(stderr, "%s:%d Error writing to directory server\n", __FILE__, __LINE__);       //DEBUG 
      } 
    int chat_count = 0; 
    int offset = 0; 
    for(;;) //read until server response 
    { 
      if(select(dir_sockfd+1, &readset, NULL, NULL, NULL) > 0) 
      { 
        if (FD_ISSET(dir_sockfd, &readset)) 
        { 
          int p_result;
          ssize_t nread = SSL_read(directory_ssl, s_d1, MAX); 
          fprintf(stderr, "%s", s_d1);
          if (nread <= 0) 
          { 
            /* Not every error is fatal. Check the return value and act accordingly. */             
            //fprintf(stderr, "%s:%d Error reading from directory server\n", __FILE__, __LINE__); 
            //DEBUG 
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
    if(strncmp(s_d1, "No chats online\n", MAX * 10) != 0) 
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
          strncpy(server_names[id], name, MAX - 1);
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
            int n1 = snprintf(s_d2, MAX, "c%s\n", server_names[index]);
            snprintf(chat_server_selection, MAX, "c%s\n", server_names[index]);
            ssize_t nwrite1 = SSL_write(directory_ssl, s_d2, n1);
            if(nwrite <= 0) {
      			  fprintf(stderr, "%s:%d Error writing to directory server\n", __FILE__, __LINE__); //DEBUG
              loop = 1;
            }
            else
            {
              loop = 0;
            }
          }
          else 
          {
            fprintf(stderr,"\nPlease enter a valid index\n");
            loop = 1;
          }
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
      fprintf(stderr,"Please try again later!");
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
    return;
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

  
  BIO *bio_chat;
  //Create a BIO object
  bio_chat = BIO_new(BIO_s_socket());
  if(bio_chat == NULL)
  {
    BIO_closesocket(sockfd);
    return;
  }

  //Wrap socket with BIO object
  BIO_set_fd(bio_chat, sockfd, BIO_CLOSE);

  //Associate the SSL object with the BIO object
  SSL_set_bio(chat_ssl, bio_chat, bio_chat);

  if(!SSL_set_tlsext_host_name(chat_ssl, chat_server_selection))
  {
    perror("client: Failed to set SNI hostname");
    return;
  }

  if(!SSL_set1_host(chat_ssl, chat_server_selection))
  {
    perror("client: Failed to set certificate verification hostname");
    return;
  }

  if(SSL_connect(chat_ssl) < 1)
  {
    perror("client: Failed to connect to server");

    if(SSL_get_verify_result(chat_ssl) != X509_V_OK)
    {
      fprintf(stderr, "Verify error: %s\n", X509_verify_cert_error_string(SSL_get_verify_result(chat_ssl)));
    }
    return;
  }

	for(;;) {

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);

		if (select(sockfd+1, &readset, NULL, NULL, NULL) > 0)
		{
			char s[MAX] = {'\0'};

			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset)) {
				if (1 == scanf(" %100[^\t\n]", s)) { /* reads until there is a tab or new line and up to 100 characters */
					/* Send the user's message to the server */
          char s1[MAX] = {'\0'};
          int n = snprintf(s1, MAX, "%s", s);
					ssize_t nwrite = SSL_write(chat_ssl, s1, n);
          /* Following lines cited from https://en.wikipedia.org/wiki/ANSI_escape_code#Fe_Escape_sequences 
          Deletes the current "Enter message: " string when typing in a chat message */
          fprintf(stderr, "\x1b[1F"); //Move cursor to previous line
          fprintf(stderr, "\x1b[2K"); //Delete content on this line
         
          if(nwrite <= 0) {
					  fprintf(stderr, "%s:%d Error writing to server\n", __FILE__, __LINE__); //DEBUG
          }
				} else {
					fprintf(stderr, "%s:%d Error reading or parsing user input\n", __FILE__, __LINE__); //DEBUG
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) {
        ssize_t nread = SSL_read(chat_ssl, s, MAX);
        if (nread <= 0) {
          /* Not every error is fatal. Check the return value and act accordingly. */
          fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__); //DEBUG
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
