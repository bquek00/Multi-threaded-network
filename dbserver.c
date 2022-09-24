#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <pthread.h>
#include <stringstore.h>
#include <csse2310a4.h>
#include <semaphore.h>
#include <csse2310a3.h>
#include <signal.h>

#define MIN_ARGS 3
#define MAX_ARGS 4
#define OPTIONAL_PORT 4
#define MIN_PORT_NUM 1024
#define MAX_PORT_NUM 65535
#define PUBLIC_KEY_LOCATION 8
#define PRIVATE_KEY_LOCATION 9

/* A struct to store all the statistics regarding client connections to the 
 * server.
 */
struct Statistics {
    int* connected;
    int* completed;
    int* authFails;
    int* gets;
    int* puts;
    int* deletes;
    sigset_t* signalMask;
};

/* A struct to store the parameters to be passed onto a client thread.*/
struct Param {
    int* fdPtr;
    StringStore* dataBase;
    StringStore* dataBasePrivate;
    char* authString;
    sem_t* guard;
    struct Statistics* stats;
    int connections;
};

int check_args(int argc, char* argv[]);
int process_int(char* str);
int open_listen(const char* port);
void process_connections(int fdServer, StringStore* dataBase, 
	StringStore* dataBasePrivate, sem_t* guard, char* authString, 
	struct Statistics* stats, int connections);
void* client_thread(void* arg);
void innit_lock(sem_t* guard);
void take_lock(sem_t* guard);
void release_lock(sem_t* guard);
char* check_address(char* address);
int check_auth_string(HttpHeader** headers, char* authString);
void* signal_handler(void* arg);
char* get(const char* key, struct Statistics* stats, StringStore* dataBase);
char* put(const char* key, struct Statistics* stats, StringStore* dataBase,
	char* body);
char* delete(const char* key, struct Statistics* stats, StringStore* dataBase);
char* bad_request();
char* not_authorized(struct Statistics* stats);
void send_service_unavailable(FILE* to);
char* process_port(char* port);
char* process_auth_file(char* fileName);
void main_loop(struct Statistics* stats, struct Param* param, 
	char* authString, FILE* to, FILE* from);

int main(int argc, char* argv[]){
    if (argc < MIN_ARGS || MAX_ARGS > 4) {
	fprintf(stderr, "Usage: dbserver authfile connections [portnum]\n");
	exit(1);
    }
    int connections = process_int(argv[2]);
    if (connections < 0) {
	fprintf(stderr, "Usage: dbserver authfile connections [portnum]\n");
	exit(1); 
    }
    char* port;
    if (argc == OPTIONAL_PORT) {
	port = process_port(argv[3]);
    } else {
	port = "0";
    }
    char* authString = process_auth_file(argv[1]);

    static sigset_t signalMask; //Set up signal handler.
    struct Statistics stats; 
    int connected = 0, completed = 0, authFails = 0, gets = 0, puts = 0, 
            deletes = 0;
    stats.connected = &connected;
    stats.completed = &completed;
    stats.authFails = &authFails;
    stats.gets = &gets;
    stats.puts = &puts;
    stats.deletes = &deletes;
    stats.signalMask = &signalMask;
    
    pthread_t threadID;
    sigemptyset(&signalMask);
    sigaddset(&signalMask, SIGHUP);
    pthread_sigmask (SIG_BLOCK, &signalMask, NULL);
    pthread_create(&threadID, NULL, signal_handler, &stats);
    
    int fdServer; // Start the server
    StringStore* dataBase = stringstore_init();
    StringStore* dataBasePrivate = stringstore_init();
    sem_t guard;
    innit_lock(&guard);
    fdServer = open_listen(port);

    process_connections(fdServer, dataBase, dataBasePrivate, &guard, 
	    authString, &stats, connections);
    stringstore_free(dataBase);
    stringstore_free(dataBasePrivate);
    sem_destroy(&guard);
    pthread_detach(threadID);
    return 0;
}

/* process_port()
 * -------------
 * Check if the given port is valid. 
 *
 * port: The port from the command line.
 *
 * Returns the port if valid exits 1 otherwise. 
 */
char* process_port(char* port) {
    int portNum = process_int(port);	
    if ((portNum < MIN_PORT_NUM || portNum > MAX_PORT_NUM) && portNum != 0) {
	fprintf(stderr, 
		"Usage: dbserver authfile connections [portnum]\n");    
	exit(1); 
    } 
    return port;
}

/* process_auth_file()
 * ------------------
 * Checks if the authentication file is a valid filel
 *
 * Returns: The authentication string if valid, Exits 2 otherwise.
 */
char* process_auth_file(char* fileName) {
    FILE* authFile = fopen(fileName, "r");
    if (!authFile) {
	fprintf(stderr, "dbserver: unable to read authentication string\n");
	exit(2);
    }
    char* authString = read_line(authFile);
    if (!authString) {
	fprintf(stderr, "dbserver: unable to read authentication string\n");
	exit(2);
    }
    fclose(authFile);
    return authString;
}

/* open_listen()
 * Listens on a given port and return the listening socket. Exits on failure.
 *
 * port: The port to be listened to.
 *
 * Returns: The listening socket.
 */
int open_listen(const char* port) {
    struct addrinfo* ai = 0;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int err;
    if ((err=getaddrinfo(NULL, port, &hints, &ai))) {
	freeaddrinfo(ai);
	fprintf(stderr, "dbserver: unable to open socket for listening\n");
	exit(3);
    }

    // Create socket and bind it to a port
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);

    // Allow address to be reused immediately
    int opVal = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, 
            &opVal, sizeof(int)) < 0) {
	fprintf(stderr, "dbserver: unable to open socket for listening\n");
	exit(3);  
    }

    if (bind(listenfd, (struct sockaddr*)ai->ai_addr, 
            sizeof(struct sockaddr)) < 0) {
	fprintf(stderr, "dbserver: unable to open socket for listening\n"); 
	exit(3);
    }

    // get port number
    struct sockaddr_in ad;
    memset(&ad, 0, sizeof(struct sockaddr_in));
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(listenfd, (struct sockaddr*)&ad, &len)) {
	fprintf(stderr, "dbserver: unable to open socket for lsitening\n");
	exit(3);
    }
    fprintf(stderr, "%u\n", ntohs(ad.sin_port));
    fflush(stderr);

    if (listen(listenfd, 10) < 0) {
	fprintf(stderr, "dbserver: unable to open socket for listening\n");
	exit(3);
    }

    return listenfd;
}

/* Process_connections
 * ------------------
 *  Processes a connection given the listeing socket.
 *
 *  fdServer: A listening socket.
 *  dataBase: The public data base.
 *  dataBasePrivate: The private date base.
 *  stats: The server statistics
 *  Guard: The semiphore guard.
 *  authString: The authentication String
 *  connections: Client connections. 
 */
void process_connections(int fdServer, StringStore* dataBase, 
	StringStore* dataBasePrivate, sem_t* guard, char* authString,
	struct Statistics* stats, int connections) {
    int fd;
    struct sockaddr_in fromAddr;
    socklen_t fromAddrSize;

    // Repeat accept connections and process
    while (1) {
	fromAddrSize = sizeof(struct sockaddr_in);
	fd = accept(fdServer, (struct sockaddr*)&fromAddr, &fromAddrSize);
	if (fd < 0) {
	    fprintf(stderr, "dbserver: unable to open socket for listening\n");
	    exit(3);
	}

	int* fdPtr = malloc(sizeof(int));
	*fdPtr = fd; 
	struct Param param;
	param.fdPtr = fdPtr;
	pthread_t threadId;
	param.dataBase = dataBase;
	param.dataBasePrivate = dataBasePrivate;
	param.authString = authString;
	param.guard = guard;
	param.stats = stats;
	param.connections = connections;
	pthread_create(&threadId, NULL, client_thread, &param);
	pthread_detach(threadId);
    }
}

/* client_thread()
 * --------------
 * Client handler for spawned thread.
 *
 * arg: The parameter struct for the client thread.
 *
 * Returns: NULL
 */
void* client_thread(void* arg) {
    struct Param* param = (struct Param*)arg;
    int fd = *(param->fdPtr);
    char* authString = param->authString;
    struct Statistics* stats = param->stats;
    int maxConnections = param->connections;
    
    // Get the request
    int fd2 = dup(fd);
    FILE* to = fdopen(fd, "w");
    FILE* from = fdopen(fd2, "r");

    take_lock(param->guard);
    if (((*(stats->connected) + 1) > maxConnections) && maxConnections != 0) {
	send_service_unavailable(to);
	fclose(to);
	fclose(from);
	return NULL;
    }
    release_lock(param->guard);

    take_lock(param->guard);
    (*(stats->connected))++;
    release_lock(param->guard);
   
    main_loop(stats, param, authString, to, from);


    take_lock(param->guard);
    (*(stats->connected))--;
    (*(stats->completed))++;
    release_lock(param->guard);

    fclose(to);
    fclose(from);
    return NULL;
}

/* main_loop()
 * -----------
 *  Start the main lopp to wait for HTTP requests, 
 *  	one at a time, over the socket.
 *
 *  stats: The struct containing all statistics for the server.
 *  param: The parameters struct passed to the client thread.
 *  authString: The authentication string. 
 *  to: The file to write to the client.
 *  from: The file to receive from the client. 
 */
void main_loop(struct Statistics* stats, 
	struct Param* param, char* authString, FILE* to, FILE* from) {
    char* method, *address, *body;
    HttpHeader** headers;
    StringStore* dataBase;

    while (get_HTTP_request(from, &method, &address, &headers, &body)) {
	take_lock(param->guard);
	// Check method
	char* response;
	char* addressType = check_address(address);
	// Check private or public
	int authenticated = 1; // Set to True by default.
	dataBase = param->dataBase;
	const char* key = address + PUBLIC_KEY_LOCATION;
	if (addressType && !strcmp(addressType, "private")) {
	    dataBase = param->dataBasePrivate;
	    key = address + PRIVATE_KEY_LOCATION;
	    authenticated = check_auth_string(headers, authString);
	}

	if (authenticated) {
	    if (!strcmp(method, "GET") && addressType) {
		response = get(key, stats, dataBase);
	    } else if (!strcmp(method, "PUT") && addressType) {
		response = put(key, stats, dataBase, body); 
	    } else if (!strcmp(method, "DELETE") && addressType) {
		response = delete(key, stats, dataBase);
	    } else {
		response = bad_request(); 
	    }
	} else {
	    response = not_authorized(stats);
	}
	release_lock(param->guard);
	fprintf(to, response);
	fflush(to);
	free(method);
	free(address);
	free(response);
	free(body);
	free_array_of_headers(headers);
    }
}

/* get()
 * -----
 * Searches for the given key in the given databse, update the given
 * 	statistics as required and return a string containing the appropriate
 * 	HTTP response. 
 *
 * key: The key whose value is to be looked for. 
 * stats: The statistics struct of the server.
 * dataBase: The database to search for the key. 
 *
 * Returns: A string of the appropriate HTTP response. 
 */
char* get(const char* key, struct Statistics* stats, StringStore* dataBase) {
    int status;
    char* statusExplanation, *responseBody, *response; 
    HttpHeader* responseHeaders[2];
    const char* value = stringstore_retrieve(dataBase, key);
    responseHeaders[0] = (HttpHeader*) malloc(sizeof(HttpHeader));
    responseHeaders[0]->name = "Content-Length";
    responseHeaders[1] = 0;
    if (value) {
	status = 200;
	statusExplanation = "OK";
	responseHeaders[0]->value = 
                (char*) malloc((sizeof(char) * strlen(value)) + 1);
	sprintf(responseHeaders[0]->value, "%ld", strlen(value));
	responseBody = (char*) malloc(sizeof(char) * strlen(value) + 1);
	strcpy(responseBody, value);
	(*(stats->gets))++;
    } else {
	status = 404;
	statusExplanation = "Not Found";
	responseHeaders[0]->value = (char*) malloc(sizeof(char) + 1);
	sprintf(responseHeaders[0]->value, "0");
	responseBody = "";	
    }

    response = construct_HTTP_response(status, statusExplanation,
            responseHeaders, responseBody);
    if (value) {
	free(responseBody);
    }
    free(responseHeaders[0]->value);
    free(responseHeaders[0]);
    return response;
}

/* put()
 * -----
 *  Puts a given key value pair to a given dataBase and updates the 
 *  statistics as required. 
 *
 *  key: The key of the key value pair to be added. 
 *  body: The value of the key value pair to be added. 
 *  stats: The statistics struct to be updates. 
 *  dataBase: The database to be searched. 
 *
 * returns: A string representing the appropriate HTTP response. 
 */
char* put(const char* key, struct Statistics* stats, StringStore* dataBase,
	char* body) {
    int status;
    char* statusExplanation, *responseBody, *response; 
    HttpHeader* responseHeaders[2];
    const char* value = body; 
    if (stringstore_add(dataBase, key, value)) {
	status = 200;
	statusExplanation = "OK";
	(*(stats->puts))++;
    } else {
	status = 500;
	statusExplanation = "Internal Server Error";
    }
    responseHeaders[0] = 0;
    responseBody = NULL;
    response = construct_HTTP_response(status, statusExplanation,
	    responseHeaders, responseBody);
    return response;
}

/* delete()
 * -----
 *  Deletes a given key value pair on a given dataBase.. 
 *
 *  key: The key of the key value pair to be added. 
 *  stats: The statistics struct to be updates. 
 *  dataBase: The database to be searched. 
 *
 * returns: A string representing the appropriate HTTP response. 
 */
char* delete(const char* key, struct Statistics* stats, 
	StringStore* dataBase) {
    int status;
    char* statusExplanation, *responseBody, *response; 
    HttpHeader* responseHeaders[1];
    responseHeaders[0] = 0;
    responseBody = NULL;
    if (stringstore_delete(dataBase, key)) {
	status = 200;
	statusExplanation = "OK";
	(*(stats->deletes))++;
    } else {
	status = 404;
	statusExplanation = "Not Found";
    } 
    response = construct_HTTP_response(status, statusExplanation, 
	    responseHeaders, responseBody);
    return response;
}

/* bad_request()
 * -------------
 *  Return a bad request HTTP response.
 *
 *  Returns: A string of a bad request HTTP response.
 */
char* bad_request() {
    int status = 400;
    char* statusExplanation = "Bad Request";
    char* responseBody = NULL; 
    HttpHeader* responseHeaders[1];
    responseHeaders[0] = 0;
    char* response = construct_HTTP_response(status, statusExplanation,
	    responseHeaders, responseBody);
    return response;
}

/* not_authorized()
 * ----------------
 *  Construct an Unauthorised http response and update the given statistics. 
 *
 *  stats: The statistics structure to be updated. 
 *
 *  Returns: A string containing an unauthorised http response.
 */
char* not_authorized(struct Statistics* stats) {
    int status = 401;
    char* statusExplanation = "Unauthorized";
    char* responseBody = NULL; 
    HttpHeader* responseHeaders[1];
    responseHeaders[0] = 0;
    char* response = construct_HTTP_response(status, statusExplanation,
	    responseHeaders, responseBody);
    (*(stats->authFails))++;
    return response;
}
 
/* send_service_unavailable()
 * --------------------------
 *  Sends a Service Unavailble http response to a given client. 
 *
 *  to: The file pointer to communicate to the client. 
 */
void send_service_unavailable(FILE* to) {
    int status = 503;
    char* statusExplanation = "Service Unavailable";
    char* responseBody = NULL;
    HttpHeader* responseHeaders[1];
    responseHeaders[0] = 0;
    char* response = construct_HTTP_response(status, statusExplanation,
	    responseHeaders, responseBody);
    fprintf(to, response);
    fflush(to);
}

/* process_int()
 * -------------
 * Converts a given string to an int.
 *
 * str: The string to be converted to an int.
 *
 * Returns: The int that hte given string represents or -1 if the string is
 * 	not a valid in,
 */
int process_int(char* str) {
    char* stringPart;
    int result = strtol(str, &stringPart, 10);
    if (strlen(stringPart) > 0) {
	return -1;
    }
    return result;
}

/* init_lock()
 * -----------
 * Initialise a semiphore lock.
 *
 * l: The semiphore lock. 
 *
 */
void innit_lock(sem_t* guard) {
    sem_init(guard, 0, 1);
} 

/* take_lock()
 * -----------
 *  Takes a given lock.
 *
 *  l: The semiphore lock.
 */
void take_lock(sem_t* guard) {
    sem_wait(guard);
}

/* release_lock()
 * -------------
 * Releases a given lock. 
 *
 * l: The semiphore lock. 
 */
void release_lock(sem_t* guard) {
    sem_post(guard);
}

/* check_address()
 * --------------
 * Checks whether the given address is public or private. 
 *
 * Returns: public or private depending on the address type, null otherwise. 
 */
char* check_address(char* address) {
    if (address[0] != '/') {
	return NULL;
    }
    char* tmpAddress = (char *) malloc(strlen(address) + 1);
    strcpy(tmpAddress, address);
    const char delimeter[2] = "/";
    char* token;
    token = strtok(tmpAddress, delimeter);

    if (!strcmp(token, "public")) {
	free(tmpAddress);
	return "public";
    } else if (!strcmp(token, "private")) {
	free(tmpAddress);
	return "private";
    } else {
	free(tmpAddress);
	return NULL;
    }
}

/* check_authString()
 * ------------------
 * Check whether the authentication string provided in the header matches
 * the on the in auth file.
 *
 * headers: A array of HttpHeader*
 * authString: The authentication string from the auth file.
 *
 * Returns: 1 if match 0 otherwise.
 */
int check_auth_string(HttpHeader** headers, char* authString) {
    int i = 0;
    while (headers[i]) {
	if (!strcmp(headers[i]->name, "Authorization")) {
	    if (!strcmp(headers[i]->value, authString)) {
		return 1;
	    } else {
		return 0;
	    }
	}
	i++;
    }
    return 0;
}

/* signal_handler()
 * ----------------
 * A thread to handle the SIGHUP signal.
 *
 * arg: The params containing the statistics for the server. 
 */
void* signal_handler(void*  arg){
    struct Statistics* stats = (struct Statistics*)arg;
    int sigCaught;
    while (1) {
        sigwait(stats->signalMask, &sigCaught);
	if (sigCaught == SIGHUP) {
	    fprintf(stderr, "Connected clients:%d\n"
		    "Completed clients:%d\nAuth failures:%d\n"
		    "GET operations:%d\nPUT operations:%d\n"
		    "DELETE operations:%d\n", *(stats->connected), 
		    *(stats->completed), *(stats->authFails), *(stats->gets), 
		    *(stats->puts), *(stats->deletes));
	    fflush(stderr);
	}
    }
    return NULL;
}

