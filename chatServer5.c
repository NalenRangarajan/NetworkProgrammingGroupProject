#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <unistd.h>
#include "inet.h"
#include "common.h"

int main(int argc, char **argv)
{
	struct sockaddr_in cli_addr, serv_addr, dir_serv_addr;
	fd_set readset;
  int  usercount = 0;
	int	 newsockfd;
  int  port;
  char chatname[MAX] = {'\0'};
  uint64_t options;
 
  struct entry {
    SSL* ssl;
    char* name;
    LIST_ENTRY(entry) entries;
  };
  
  LIST_HEAD(client_list, entry);

  //CTX For connecting to Directory Server

  //Create SSL_CTX object
  SSL_CTX* directory_ctx = SSL_CTX_new(TLS_client_method());
  if(directory_ctx == NULL)
  {
    perror("chatServer: Failed to create the SSL_CTX");
    return;
  }

  SSL_CTX_clear_mode(directory_ctx, SSL_MODE_AUTO_RETRY);

  //Configure to include certificate verification
  SSL_CTX_set_verify(directory_ctx, SSL_VERIFY_PEER, NULL);

  if(!SSL_CTX_set_default_verify_paths(directory_ctx))
  {
    perror("chatServer: Couldn't set default certificate store");
    return;
  }

  //Ensure minimum TLS version
  if(!SSL_CTX_set_min_proto_version(directory_ctx, TLS1_3_VERSION))
  {
    perror("chatServer: Failed to set minimum TLS version");
    return;
  }

  SSL_CTX_load_verify_locations(directory_ctx, "noPassRootCA.crt", NULL);

  //Create SSL object for directory
  SSL* directory_ssl = SSL_new(directory_ctx);
  if(directory_ssl == NULL)
  {
    perror("client: Failed to create SSL object");
    return;
  }


	/* Create communication endpoint */
	int sockfd;			/* Listening socket */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Add SO_REUSEADDRR option to prevent address in use errors (modified from: "Hands-On Network
	* Programming with C" Van Winkle, 2019. https://learning.oreilly.com/library/view/hands-on-network-programming/9781789349863/5130fe1b-5c8c-42c0-8656-4990bb7baf2e.xhtml */
	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		return EXIT_FAILURE;
	}
  
  //If command line args were correctly input
  if(argc == 3)
  {
    snprintf(chatname, "%s", argv[1]);
    if(sscanf(argv[2], "%d", &port) == 1)
    {
      if( port > 49151 && port < 65536 && port != SERV_TCP_PORT)
      {
        fprintf(stderr, "Chat Server initializing...\n");
      }
      else
      {
        fprintf(stderr, "Error: Invalid port. Port ID must be between 49151 and 65536\n");
        exit(1);
      }
    }
    else 
    {
      fprintf(stderr, "Please enter a number for your port\n");
      exit(1);
    }
  }
  else //query for remaining args
  {
    fprintf(stderr, "Enter chat name: ");
    if(scanf("%99[^\t\n]", chatname) != 1)
    {
      fprintf(stderr, "Error reading server chat name\n");
      exit(1);
    }
    
    fprintf(stderr, "Enter port number (49151-65536): ");
    if(scanf("%d", &port) != 1)
    {
      fprintf(stderr, "Error reading port number\n");
      exit(1);
    }
    
    if( port > 49151 && port < 65536 && port != SERV_TCP_PORT)
    {
      fprintf(stderr, "Chat Server initializing...\n");
    }
    else
    {
      fprintf(stderr, "Error: Invalid port\n");
      exit(1);
    }
  }

  
  //CTX for connecting to ChatClients

  //Create SSL_CTX object
  SSL_CTX* chat_ctx = SSL_CTX_new(TLS_server_method());
  if(chat_ctx == NULL)
  {
    perror("Directory Server: Failed to create the SSL_CTX");
    return;
  }
  
  SSL_CTX_clear_mode(chat_ctx, SSL_MODE_AUTO_RETRY);

  //Ensure minimum TLS version
  if(!SSL_CTX_set_min_proto_version(chat_ctx, TLS1_3_VERSION))
  {
    perror("Directory Server: Failed to set minimum TLS version");
    return;
  }

  //We are assuming that CPU exhaustion attacks will not occur so |= SSL_OP_No_RENEGOTIATION is not necessary
  options = SSL_OP_IGNORE_UNEXPECTED_EOF;

  SSL_CTX_set_options(chat_ctx, options);
  
  char filename1[100];
  
  char filename2[100];

  if(strncmp(chatname, "Anime", MAX) == 0)
  {
    snprintf(filename1, "Anime.crt", MAX);


    snprintf(filename2, "noPassAnime.key", MAX);
  }
  else if(strncmp(chatname, "Sports", MAX) == 0)
  {
    snprintf(filename1, "Sports.crt", MAX);


    snprintf(filename2, "noPassSports.key", MAX);
  }
  else if(strncmp(chatname, "Video Games", MAX) == 0)
  {
    snprintf(filename1, "VideoGames.crt", MAX);


    snprintf(filename2, "noPassVideoGames.key", MAX);
  }
  else
  {
    return;
  }

  if(SSL_CTX_use_certificate_chain_file(chat_ctx, filename1) <= 0)
  {
    SSL_CTX_free(chat_ctx);
    ERR_print_errors_fp(stderr);
    perror("Failed to load the server certificate chain file");
  }

  if(SSL_CTX_use_PrivateKey_file(chat_ctx, filename2, SSL_FILETYPE_PEM) <= 0)
  {
    SSL_CTX_free(chat_ctx);
    ERR_print_errors_fp(stderr);
    perror("Error loading server private key file");
  }

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family 		= AF_INET;
	serv_addr.sin_addr.s_addr 	= htonl(INADDR_ANY);
	serv_addr.sin_port			= htons(port);

	/* Bind to local IP/port before registering with the Directory Server to ensure
	* that the port is available */
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	/* Create communication endpoint */
	int dir_sockfd;
	if ((dir_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	/* Bind socket to server address */
	memset((char *) &dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family 		= AF_INET;
	dir_serv_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);	/* hard-coded in inet.h */
	dir_serv_addr.sin_port			= htons(SERV_TCP_PORT);			/* hard-coded in inet.h */

	/* Connect to the server. */
	if (connect(dir_sockfd, (struct sockaddr *) &dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("server: can't connect to directory server");
		return EXIT_FAILURE;
	}

  BIO *dir_bio;
  //Create a BIO object
  dir_bio = BIO_new(BIO_s_socket());
  if(dir_bio == NULL)
  {
    BIO_closesocket(dir_sockfd);
    return;
  }

  //Wrap socket with BIO object
  BIO_set_fd(dir_bio, dir_sockfd, BIO_CLOSE);

  //Associate the SSL object with the BIO object
  SSL_set_bio(directory_ssl, dir_bio, dir_bio);

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
  
 	/* Register with the directory server */
  char s_dir[MAX] = {'\0'};
  int n_dir = snprintf(s_dir, MAX, "s%s %d", chatname, port);
  ssize_t nwrite_dir = SSL_write(directory_ssl, s_dir, n_dir);
  if(nwrite_dir < 0) {
	  fprintf(stderr, "%s:%d Error writing to directory server\n", __FILE__, __LINE__); //DEBUG
    exit(1);
  }
  
  for(;;) {

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(dir_sockfd, &readset);

		if (select(dir_sockfd+1, &readset, NULL, NULL, NULL) > 0)
		{ 
      if (FD_ISSET(dir_sockfd, &readset))  
      {
          char s_dir1[MAX] = {'\0'};
  				ssize_t nread = SSL_read(directory_ssl, s_dir1, MAX);
  				if (nread <= 0) {
  					/* Not every error is fatal. Check the return value and act accordingly. */
  					fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__); //DEBUG
  				}
          s_dir1[nread] = '\0';
          if(strncmp(s_dir1, "Connected!\n",11) == 0){
  					fprintf(stderr, "%s", s_dir1);
            break;
          }
          /*
          We want to quit reading when we see Connected!, but we will see Chat directory: first so we want to do nothing here 
          */
          else if(strncmp(s_dir1, "Chat directory:\n", MAX) == 0)
          {
          //do nothing
          }
          else
          {
  					fprintf(stderr, "%s", s_dir1);
            exit(1);
          }
       }
		}
	}
 
  


	/* Now you are ready to accept client connections */
	listen(sockfd, 5);

  BIO *cli_bio;
  //Create a BIO object
  cli_bio = BIO_new(BIO_s_accept());
  if(cli_bio == NULL)
  {
    BIO_closesocket(sockfd);
    return;
  }

  //Wrap socket with BIO object
  BIO_set_fd(cli_bio, sockfd, BIO_CLOSE);
  
 
  /* linked list operations */
  struct entry *cli, *clj;
  
  struct client_list head;     /* List head */
  
  LIST_INIT(&head);            /* Initialize client socket list */


	for (;;) {
    //clear error stack
    ERR_clear_error();
    /* Initialize and populate your readset and compute maxfd */
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		/* We won't write to a listening socket so no need to add it to the writeset */
		int max_fd = sockfd;
   
    /* This should populate readset with client sockets */
    LIST_FOREACH(cli, &head, entries)
    {
      FD_SET(SSL_get_fd(cli->ssl), &readset);
      
		  /* Compute max_fd as you go */
		  if (max_fd < SSL_get_fd(cli->ssl)) {max_fd = SSL_get_fd(cli->ssl);}
    }
   
    if (select(max_fd+1, &readset, NULL, NULL, NULL) > 0) {

			/* Check to see if our listening socket has a pending connection */
			if (FD_ISSET(sockfd, &readset)) {
				/* Accept a new connection request */
				socklen_t clilen = sizeof(cli_addr);
				if(BIO_do_accept(cli_bio) <= 0)
        {
          //Client disappeared during connection
					perror("server: accept error");	
          continue;
        }
        BIO* client_bio = BIO_pop(cli_bio);

        SSL* ssl;
        if((ssl = SSL_new(chat_ctx)) == NULL)
        {
          ERR_print_errors_fp(stderr);
          warnx("Error creating SSL handle for new connection");
          BIO_free(cli_bio);
          continue;
        }

        SSL_set_bio(ssl, cli_bio, cli_bio);

        //attempt handshake
        if(SSL_accept(ssl) <= 0)
        {
          ERR_print_errors_fp(stderr);
          warnx("Error performing SSL handshake with client");
          SSL_free(ssl);
          continue;
        }
        
        //Add new chat clients
        struct entry *new_entry;
        new_entry = malloc(sizeof(struct entry));
        new_entry->ssl = ssl;
        new_entry->name = NULL;
        LIST_INSERT_HEAD(&head, new_entry, entries);
        
        char s1[MAX] = {'\0'};
        int n = snprintf(s1, MAX, "Enter a nickname: ");
        ssize_t nwrite = SSL_write(new_entry->ssl, s1, n);
        if(nwrite < 0) {
				  fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
        }
      }
      
      
      LIST_FOREACH(cli, &head, entries)
      {
  			if (FD_ISSET(SSL_get_fd(cli->ssl), &readset)) {
  
  				char s[MAX] = {'\0'};
  				ssize_t nread = SSL_read(cli->ssl, s, MAX);
  				if (nread <= 0) {
  					/* Not every error is fatal. Check the return value and act accordingly. */
  					close (SSL_get_fd(cli->ssl));
            LIST_REMOVE(cli, entries);
            if(cli->name)
            {
              char s1[MAX]= {'\0'};
              int n = snprintf(s1, MAX, "%s has left the chat\nEnter message: ", cli->name);
              LIST_FOREACH(clj, &head, entries)
              {
                ssize_t nwrite = SSL_write(clj->ssl, s1, n);
                if(nwrite < 0) {
      					  fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
                }
              }
              if(cli->name)
              {
                free(cli->name);
                usercount--;
              }
              free(cli);
              continue;
            }
  				}
          
          if(cli->name == NULL) /* New login */
          {
            int unique_name = 1;
            char s1[MAX] = {'\0'};
            LIST_FOREACH(clj, &head, entries)
            {
              if(clj->name && strncmp(s, clj->name, MAX) == 0)
              {
                unique_name = 0;
              }
            }
            if(unique_name)
            {
              cli->name = malloc(MAX);
              snprintf(cli->name, MAX, "%s", s);
              usercount++;
              int n = 0;
              if(usercount == 1)
              {
                n = snprintf(s1, MAX, "You are the first user to join the chat\nEnter message: ");
              }
              else
              {
                n = snprintf(s1, MAX, "%s has joined the chat\nEnter message: ",cli->name);
              }
              LIST_FOREACH(clj, &head, entries)
              {
                if(clj->name)
                {
                  ssize_t nwrite = SSL_write(clj->ssl, s1, n);
                  if(nwrite < 0) {
        					  fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
                  }
                }
              }
            }
            else
            {
              /* send signal to disconnect client */
              int n = snprintf(s1, MAX, "You entered a duplicate username. Please enter a new username.\nEnter nickname: ");
              ssize_t nwrite = SSL_write(cli->ssl, s1, n);
              if(nwrite < 0) {
    					  fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
              }
            }
          }
          else /* Standard Message */
          {
            char s1[MAX] = {'\0'};
            int n = snprintf(s1, MAX, "%s: %s\nEnter message: ", cli->name, s);
            LIST_FOREACH(clj, &head, entries)
            {
    				  /* Send the reply to the clients */
              ssize_t nwrite = SSL_write(clj->ssl, s1, n);
              if(nwrite < 0) {
    					  fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
              }
            }
          }
  			}
        else {
  			  /* Handle select errors */
          continue; //try again
  		  }
  		}
    }
	}
	// return or exit(0) is implied; no need to do anything because main() ends
}