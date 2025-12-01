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
	struct sockaddr_in cli_addr, serv_addr;
	fd_set readset;
	int	 newsockfd;
  uint64_t options;
 
  struct entry {
    SSL* ssl;
    char* ipaddress;
    int portnum;
    char* name;
    LIST_ENTRY(entry) entries;
  };
  
  LIST_HEAD(server_list, entry);

  //Create SSL_CTX object
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if(ctx == NULL)
  {
    perror("Directory Server: Failed to create the SSL_CTX");
    return;
  }
  
  SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);

  //Ensure minimum TLS version
  if(!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION))
  {
    perror("Directory Server: Failed to set minimum TLS version");
    return;
  }

  //We are assuming that CPU exhaustion attacks will not occur so |= SSL_OP_NO_RENEGOTIATION is not necessary
  options = SSL_OP_IGNORE_UNEXPECTED_EOF;

  SSL_CTX_set_options(ctx, options);

  if(SSL_CTX_use_certificate_chain_file(ctx, "noPassDirectory.crt") <= 0)
  {
    SSL_CTX_free(ctx);
    ERR_print_errors_fp(stderr);
    perror("Failed to load the server certificate chain file");
  }

  if(SSL_CTX_use_PrivateKey_file(ctx, "noPassDirectory.key", SSL_FILETYPE_PEM) <= 0)
  {
    SSL_CTX_free(ctx);
    ERR_print_errors_fp(stderr);
    perror("Error loading server private key file");
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

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family		= AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port		= htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	listen(sockfd, 5);

  BIO *bio;
  //Create a BIO object
  bio = BIO_new(BIO_s_accept());
  if(bio == NULL)
  {
    BIO_closesocket(sockfd);
    return;
  }

  //Wrap socket with BIO object
  BIO_set_fd(bio, sockfd, BIO_CLOSE);
  
  /* linked list operations */
  struct entry *cli, *clj;
  
  struct server_list head;     /* List head */
  
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
        if(BIO_do_accept(bio) <= 0)
        {
          //Client disappeared during connection
					perror("server: accept error");	
          continue;
        }
        BIO* client_bio = BIO_pop(bio);
        fprintf(stderr, "New client connection accepted\n");
        SSL* ssl;
        if((ssl = SSL_new(ctx)) == NULL)
        {
          ERR_print_errors_fp(stderr);
          warnx("Error creating SSL handle for new connection");
          BIO_free(client_bio);
          continue;
        }

        SSL_set_bio(ssl, client_bio, client_bio);

        //attempt handshake
        if(SSL_accept(ssl) <= 0)
        {
          ERR_print_errors_fp(stderr);
          warnx("Error performing SSL handshake with client");
          SSL_free(ssl);
          continue;
        }
        
        //Create Chat Server entry
        struct entry *new_entry;
        new_entry = malloc(sizeof(struct entry));
        new_entry->ssl = ssl;
        new_entry->name = NULL;
        new_entry->ipaddress = NULL;
        new_entry->ipaddress = malloc(MAX);
        strncpy(new_entry->ipaddress, inet_ntoa(cli_addr.sin_addr), MAX);
        LIST_INSERT_HEAD(&head, new_entry, entries);
        ssize_t nwrite = SSL_write(new_entry->ssl, "Chat directory:\n", 17); 
        if(nwrite <= 0) 
        { 
          fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG }
        }
      }

		  /* Iterate through your client and server sockets */
   
      cli = LIST_FIRST(&head);
      while(cli != NULL)
      {
        struct entry *next = LIST_NEXT(cli, entries);
  			if (FD_ISSET(SSL_get_fd(cli->ssl), &readset)) {
  
  				char s[MAX] = {'\0'};
          ssize_t nread = SSL_read(cli->ssl, s, MAX);
          fprintf(stderr, "%s", s);
          fprintf(stderr, "Read %d\n", nread);
          if (nread <= 0) {
            /* Not every error is fatal. Check the return value and act accordingly. */
            SSL_free(cli->ssl);
            LIST_REMOVE(cli, entries);
            if(cli->name)
            {              
              if(cli->name)
              {
                free(cli->name);
              }
              if(cli->ipaddress)
              {
                free(cli->ipaddress);
              }
              free(cli);
            }
            cli = next;
            continue;
          }         
          
          fprintf(stderr, "before c check");
          if (s[0] == 'c') { //reading from a client            
            if(strnlen(s, MAX) == 1) //If client queries active chats then only 's' was sent
            {
              fprintf(stderr, "Inside c check");
              int index = 0;
              int n = 0;
              char s1[MAX * 10] = {'\0'};
              ssize_t offset = 0;
              LIST_FOREACH(clj, &head, entries)
              {
                //write all active servers into the s1 buffer
                if(clj->name && clj->ipaddress)
                {
                  n = snprintf(s1 + offset, MAX * 10 - offset, "%d. Name: %s, IP Address: %s, Port Number: %d\n", index, clj->name, clj->ipaddress, clj->portnum);
                  
                  offset += n;
                  index++;
                }
              }
              fprintf(stderr, "Before index check");
              if(index == 0)
              {
                n = snprintf(s1 + offset, MAX * 10 - offset, "No chats online\n");
                offset += n;
              }
              else
              {
                n = snprintf(s1 + offset, MAX * 10 - offset, "Select server: ");
                offset += n;
              }
              
              fprintf(stderr, "Before no chats write");
              ssize_t nwrite = SSL_write(cli->ssl, s1, offset);
              fprintf(stderr, "After no chats write, %d", nwrite);
              if(nwrite <= 0) {
                fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
              }
            }
            else //client picks a chat
            {
              char server_name[MAX] = {'\0'};
              //grab server name from client request
              if(sscanf(s, "c%99[^\n]", server_name) == 1)
              {
                int found = 0;
                LIST_FOREACH(clj, &head, entries)
                {
                  if(clj->name && strncmp(clj->name, server_name, strnlen(server_name, MAX)) == 0) //servers are only named entities
                  {
                    found = 1;
                    int n = 0;
                    char s1[MAX] = {'\0'};
                    n = snprintf(s1, MAX, "%s %d",clj->ipaddress, clj->portnum);
                    ssize_t nwrite = SSL_write(cli->ssl, s1, n);
                    if(nwrite <= 0) {
                      fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
                    } 
                  }
                }
                if(found == 0)
                {
                  char s1[MAX] = {'\0'};
                  int n = snprintf(s1, MAX, "fail");
                  ssize_t nwrite = SSL_write(cli->ssl, s1, n);
                  if(nwrite <= 0) {
                    fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
                  }
                } 
              }
            }
          }
          else if (s[0] == 's') //reading from a server
          {
            char *s1 = calloc(1, strnlen(s, MAX) + 1);
            snprintf(s1, strnlen(s, MAX), "%s", s + 1);
            char temp_name[100];
            int temp_port = 0;
            //get name and port number from s
            if(sscanf(s1, "%99[^0-9] %d", temp_name, &temp_port) == 2)
            {
              int unique_name = 1;
              LIST_FOREACH(clj, &head, entries)
              {
                if(clj->name && strncmp(temp_name, clj->name, MAX) == 0)
                {
                  unique_name = 0;
                }
              }
              if(unique_name == 0)
              {
                ssize_t nwrite = SSL_write(cli->ssl, "There is already a chat server with this name. Please try again!\n", 63);
                if(nwrite <= 0) {
                  fprintf(stderr, "%s:%d Error writing to server\n", __FILE__, __LINE__); //DEBUG
                }
                SSL_free(cli->ssl);
                LIST_REMOVE(cli, entries);
                if(cli->name)
                {              
                  if(cli->name)
                  {
                    free(cli->name);
                  }
                  if(cli->ipaddress)
                  {
                    free(cli->ipaddress);
                  }
                  free(cli);
                  continue;
                }
              }
              else //Add server
              {
                ssize_t nwrite = SSL_write(cli->ssl, "Connected!\n", 11);
                if(nwrite <= 0) {
                  fprintf(stderr, "%s:%d Error writing to server\n", __FILE__, __LINE__); //DEBUG
                }
                cli->name = malloc(MAX);
                snprintf(cli->name, MAX, "%s", temp_name);
                cli->portnum = temp_port;
                cli->ipaddress = malloc(MAX);
                snprintf(cli->ipaddress, MAX, "%s", inet_ntoa(cli_addr.sin_addr));
              }
            }
            else
            {
              fprintf(stderr, "%s:%d Error parsing chat server arguments\n", __FILE__, __LINE__); //DEBUG
            }
          }
          else {
            snprintf(s, MAX, "Invalid request");
          }
        } 
        cli = next; 
      }
    }

		else {
			/* Handle select errors */
		}
	}
}
