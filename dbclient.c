#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <csse2310a4.h>

#define MIN_ARGS 3

void send_get(char* key, FILE* to, FILE* from);
int check_key(char* key);
void send_put(char* key, char* value, FILE* to, FILE* from);

int main(int argc, char** argv) {
    if (argc < MIN_ARGS) {
	fprintf(stderr, "Usage: dbclient portnum key [value]\n");
	exit(1);
    }

    char* key = argv[2];
    if (!check_key(key)) {
	fprintf(stderr, "dbclient: key must not contain spaces or newlines\n");
	exit(1);
    }

    // Set up the server 
    const char* port = argv[1];
    struct addrinfo* ai = 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("localhost", port, &hints, &ai)) {
	fprintf(stderr, "dbclient: unable to connect to port %s\n", port);
	exit(2);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, (struct sockaddr*)ai->ai_addr, sizeof(struct sockaddr))) {
    	fprintf(stderr, "dbclient: unable to connect to port %s\n", port);
	exit(2);
    }

    int fd2 = dup(fd);
    FILE* to = fdopen(fd, "w");
    FILE* from = fdopen(fd2, "r");

    // Send HTTP
    if (argc == 3) {
	send_get(key, to, from);
    } else {
	char* value = argv[3];
	send_put(key, value, to, from);
    }

    fclose(from);
}

/* send_get()
 * ---------
 *  Send a GET http request with the given key and and process the 
 *  	appropriate response. 
 *
 *  key: The key to be requested form the server. 
 *  to: The file to write to the server.
 *  from: The file to read from the server
 */
void send_get(char* key, FILE* to, FILE* from) {
    int status;
    char* statusExplanation, *body;
    HttpHeader** headers;

    char* response = "GET /public/%s HTTP/1.1\r\n\r\n";
    fprintf(to, response, key);
    fflush(to);
    fclose(to);	
    if (get_HTTP_response(from, &status, 
            &statusExplanation, &headers, &body)) {
	if (status == 200) {
	    fprintf(stdout, "%s\n", body);
	} else {
	    exit(3);
	}
    } else {
	exit(3);
    }

}

/* send_put()
 * ---------
 *  Send a PUT http request with the given key and and process the 
 *  	appropriate response. 
 *
 *  key: The key to be added to the database on the server. 
 *  value: The value to be added to the database on the server.
 *  to: The file to write to the server.
 *  from: The file to read from the server
 */
void send_put(char* key, char* value, FILE* to, FILE* from) {
    int status;
    char* statusExplanation, *body;
    HttpHeader** headers;
    
    char* response = 
	    "PUT /public/%s HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s";
    fprintf(to, response, key, strlen(value), value);
    fflush(to);
    fclose(to);

    if (get_HTTP_response(from, &status,
            &statusExplanation, &headers, &body)) {
	if (status != 200) {
	    exit(4);
	}
    } else {
	exit(4);
    }
}

/* check_key()
 * ----------
 *  Check that a given key has no spaces or newlines. 
 *
 *  key: A string representing the key. 
 *
 *  Returns 1 if the key is valid, 0 otherwise. 
 */
int check_key(char* key) {
    int length = strlen(key);
    for (int i = 0; i < length; i++) {
	if (key[i] == ' ' || key[i] == '\n') {
	    return 0;
	} 
    }
    return 1;
}
