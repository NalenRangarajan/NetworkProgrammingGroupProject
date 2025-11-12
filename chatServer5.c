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
 
  struct entry {
    int socketid;
    char* name;
    LIST_ENTRY(entry) entries;
  };
  
  LIST_HEAD(client_list, entry);

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
  else
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
  
 	/* Register with the directory server */
  char s_dir[MAX] = {'\0'};
  int n_dir = snprintf(s_dir, MAX, "s%s %d", chatname, port);
  ssize_t nwrite_dir = write(dir_sockfd, s_dir, n_dir);
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
  				ssize_t nread = read(dir_sockfd, s_dir1, MAX);
  				if (nread <= 0) {
  					/* Not every error is fatal. Check the return value and act accordingly. */
  					fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__); //DEBUG
  				}
          s_dir1[nread] = '\0';
          if(strncmp(s_dir1, "Connected!\n",11) == 0){
  					fprintf(stderr, "%s", s_dir1);
            break;
          }
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
 
  /* linked list operations */
  struct entry *cli, *clj;
  
  struct client_list head;     /* List head */
  
  LIST_INIT(&head);            /* Initialize client socket list */


	for (;;) {
 
    /* Initialize and populate your readset and compute maxfd */
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		/* We won't write to a listening socket so no need to add it to the writeset */
		int max_fd = sockfd;
   
    /* This should populate readset with client sockets */
    LIST_FOREACH(cli, &head, entries)
    {
      FD_SET(cli->socketid, &readset);
      
		  /* Compute max_fd as you go */
		  if (max_fd < cli->socketid) {max_fd = cli->socketid;}
    }
   
    if (select(max_fd+1, &readset, NULL, NULL, NULL) > 0) {

			/* Check to see if our listening socket has a pending connection */
			if (FD_ISSET(sockfd, &readset)) {
				/* Accept a new connection request */
				socklen_t clilen = sizeof(cli_addr);
				newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
				if (newsockfd < 0) {
					perror("server: accept error");	
          continue;
				}
        
        struct entry *new_entry;
        new_entry = malloc(sizeof(struct entry));
        new_entry->socketid = newsockfd;
        new_entry->name = NULL;
        LIST_INSERT_HEAD(&head, new_entry, entries);
        
        char s1[MAX] = {'\0'};
        int n = snprintf(s1, MAX, "Enter a nickname: ");
        ssize_t nwrite = write(newsockfd, s1, n);
        if(nwrite < 0) {
				  fprintf(stderr, "%s:%d Error writing to client\n", __FILE__, __LINE__); //DEBUG
        }
      }
      
      
      LIST_FOREACH(cli, &head, entries)
      {
  			if (FD_ISSET(cli->socketid, &readset)) {
  
  				char s[MAX] = {'\0'};
  				ssize_t nread = read(cli->socketid, s, MAX);
  				if (nread <= 0) {
  					/* Not every error is fatal. Check the return value and act accordingly. */
  					close (cli->socketid);
            LIST_REMOVE(cli, entries);
            if(cli->name)
            {
              char s1[MAX]= {'\0'};
              int n = snprintf(s1, MAX, "%s has left the chat\nEnter message: ", cli->name);
              LIST_FOREACH(clj, &head, entries)
              {
                ssize_t nwrite = write(clj->socketid, s1, n);
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
                  ssize_t nwrite = write(clj->socketid, s1, n);
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
              ssize_t nwrite = write(cli->socketid, s1, n);
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
              ssize_t nwrite = write(clj->socketid, s1, n);
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
