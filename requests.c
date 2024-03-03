#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"

/* function that computes either a get or a delete request, based on type */
char *compute_get_delete_request(char *host, char *url, char *query_params,
                                char *cookies, char *jwt, char *type)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *helper = calloc(BUFLEN, sizeof(char));

    /* Step 1: write the method name, URL, request params (if any) and protocol type */
    if (query_params != NULL) {
        sprintf(line, "%s %s?%s HTTP/1.1", type, url, query_params);
    } else {
        sprintf(line, "%s %s HTTP/1.1", type, url);
    }

    compute_message(message, line);

    /* Step 2: add the host */
    sprintf(helper, "Host: %s", host);
    compute_message(message, helper);
    memset(helper, 0, BUFLEN);

    /* Step 3 (optional): add headers and/or cookies, according to the protocol format */
    if (cookies != NULL) {
       sprintf(helper, "Cookie: %s", cookies);
       compute_message(message, helper);
       memset(helper, 0, BUFLEN);
    }

    if (jwt != NULL) {
        sprintf(helper, "Authorization: Bearer %s", jwt);
        compute_message(message, helper);
        memset(helper, 0, BUFLEN);
    }

    /* Step 4: add final new line */
    compute_message(message, "");

    free(line);
    free(helper);
    return message;
}

char *compute_post_request(char *host, char *url, char* content_type, char **body_data,
                            int body_data_fields_count, char *cookies, char *jwt)
{
    char *message = calloc(BUFLEN, sizeof(char));
    char *line = calloc(LINELEN, sizeof(char));
    char *helper = calloc(BUFLEN, sizeof(char));

    /* write the method name, URL and protocol type */
    sprintf(line, "POST %s HTTP/1.1", url);
    compute_message(message, line);
    
    /* add host */
    sprintf(helper, "Host: %s", host);
    compute_message(message, helper);
    memset(helper, 0, BUFLEN);

    /* add necessary headers (Content-Type and Content-Length are mandatory)
     *      in order to write Content-Length you must first compute the message size
     */

    sprintf(helper, "Content-Type: %s", content_type);
    compute_message(message, helper);
    memset(helper, 0, BUFLEN);

    sprintf(helper, "Content-Length: %ld", strlen(*body_data));
    compute_message(message, helper);
    memset(helper, 0, BUFLEN);

    // Step 4 (optional): add cookies
    if (cookies != NULL) {
        sprintf(helper, "Cookie: %s", cookies);
        compute_message(message, helper);
        memset(helper, 0, BUFLEN);
    }

    if (jwt != NULL) {
        sprintf(helper, "Authorization: Bearer %s", jwt);
        compute_message(message, helper);
        memset(helper, 0, BUFLEN);
    }

    // Step 5: add new line at end of header
    strcat(message, "\r\n");

    // Step 6: add the actual payload data
    compute_message(message, *body_data);

    free(line);
    free(helper);
    return message;
}
