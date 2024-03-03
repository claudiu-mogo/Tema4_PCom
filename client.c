#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "parson.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"

#define HOST "34.254.242.81"
#define PORT 8080
#define LEN 5000

char *stdin_buffer;
char *message;
char *access_route;
char *payload_type;
char *username;
char *password;
char *general_use_buffer;

/* gets rid of the newline from the end of a string if necessary */
void remove_newline(char *s)
{
    if (s[strlen(s) - 1] == '\n') {
        s[strlen(s) - 1] = 0;
    }
}

/* check if a string is the representation of a number */
int check_number(char *s)
{
    /* check blank input */
    if (strlen(s) == 0)
        return 0;
    /* first digit must not be zero */
    if (s[0] == '0')
        return 0;
    
    /* if a character is not in 0 - 9, then it is not a number */
    for (int i = 0; i < strlen(s); i++) {
        if (s[i] > '9' || s[i] < '0')
            return 0;
    }
    return 1;
}

/* function for both register and login command, varrying by type */
char *auth_login(size_t buflen, int sock_tcp, char *type)
{
    /* set access route and payload type */
    memset(access_route, 0, BUFLEN);
    sprintf(access_route, "/api/v1/tema/auth/%s", type);
    memset(payload_type,0, BUFLEN);
    sprintf(payload_type, "application/json");

    /* get credentials from the user */
    memset(username, 0, BUFLEN);
    printf("username=");
    getline(&username, &buflen, stdin);
    remove_newline(username);

    memset(password, 0, BUFLEN);
    printf("password=");
    getline(&password, &buflen, stdin);
    remove_newline(password);

    /* build JSON Object */
    JSON_Value *big_json = json_value_init_object();
    JSON_Object *registration_object = json_value_get_object(big_json);
    json_object_set_string(registration_object, "username", username);
    json_object_set_string(registration_object, "password", password);
    char *data = json_serialize_to_string(big_json);

    /* compute post request */
    message = compute_post_request(HOST, access_route, payload_type, &data, strlen(data), NULL, NULL);
    free(data);

    /* send the message to server */
    send_to_server(sock_tcp, message);

    free(message);
    json_value_free(big_json);
    return receive_from_server(sock_tcp);
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);

    int sock_tcp;
    size_t len = LEN;
    size_t buflen = BUFLEN;
    struct sockaddr_in serv_addr;

    /* alloc the buffers */
    memset(&serv_addr, 0, sizeof(serv_addr));
    stdin_buffer = calloc(LEN, sizeof(char));
    char *message;
    char *server_response;
    access_route = calloc(BUFLEN, sizeof(char));
    payload_type = calloc(BUFLEN, sizeof(char));
    username = calloc(BUFLEN, sizeof(char));
    password = calloc(BUFLEN, sizeof(char));
    general_use_buffer = calloc(BUFLEN, sizeof(char));
    char *cookie = NULL;
    char *jwt = NULL;

    puts("Enter a command:");

    /* main loop for waiting for the commands */
    while (1) {

        /* read the command from stdin */
        memset(stdin_buffer, 0, LEN);
        getline(&stdin_buffer, &len, stdin);
        remove_newline(stdin_buffer);

        if (!strcmp(stdin_buffer, "register")) {

            sock_tcp = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

            server_response = auth_login(buflen, sock_tcp, "register");

            /* check for errors */
            if (strstr(server_response, "Bad Request"))
                puts("Username already taken, try again.");
            else
                puts("200 - OK - User successfully registered.");
            
            free(server_response);
            close(sock_tcp);
        }
        else if (!strcmp(stdin_buffer, "login")) {

            /* if a user is already logged in, deny the command */
            if (cookie != NULL) {
                puts("There is a user logged in.");
                continue;
            }

            sock_tcp = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

            server_response = auth_login(buflen, sock_tcp, "login");

            if (strstr(server_response, "Bad Request")) {
                puts("Wrong credentials.");
            }
            else {

                /* save the cookie from server_response */
                char *p = strstr(server_response, "connect.sid=");
                char *q = strstr(p, ";");
                cookie = calloc(BUFLEN, sizeof(char));
                memcpy(cookie, p, q - p);
                puts("200 - OK - User successfully logged in.");
            }

            free(server_response);
            close(sock_tcp);
        }
        else if (!strcmp(stdin_buffer, "enter_library")) {
            if (cookie == NULL) {
                puts("No user is logged in.");
                continue;
            }

            sock_tcp = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

            memset(access_route, 0, BUFLEN);
            sprintf(access_route, "/api/v1/tema/library/access");

            /*compute get request*/
            message = compute_get_delete_request(HOST, access_route, NULL, cookie, NULL, "GET");

            /* send the message to server */
            send_to_server(sock_tcp, message);
            server_response = receive_from_server(sock_tcp);
            free(message);

            /* check for errors */
            if (strstr(server_response, "error")) {
                puts("Couldn't reach the library.");
                free(server_response);
                close(sock_tcp);
                continue;
            }

            /* get the JSON from the response */
            jwt = calloc(BUFLEN, sizeof(char));
            char *p = strstr(server_response, "{");
            char *q = strstr(p, "}");
            memcpy(jwt, p, q - p + 1);

            /* build JSON object to extract the jwt value */
            JSON_Value *value_from_string = json_parse_string(jwt);
            JSON_Object *obj_from_string = json_value_get_object(value_from_string);
            memset(jwt, 0, BUFLEN);
            const char *getter = json_object_get_string(obj_from_string, "token");
            strcpy(jwt, getter);

            puts("200 - OK - Entered library.");
            json_value_free(value_from_string);

            free(server_response);
            close(sock_tcp);
        }
        else if (!strcmp(stdin_buffer, "get_books")) {

            if (cookie == NULL) {
                puts("No user is logged in.");
                continue;
            }

            sock_tcp = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

            memset(access_route, 0, BUFLEN);
            sprintf(access_route, "/api/v1/tema/library/books");

            /* compute get request */
            message = compute_get_delete_request(HOST, access_route, NULL, cookie, jwt, "GET");

            /* send the message to server */
            send_to_server(sock_tcp, message);
            server_response = receive_from_server(sock_tcp);
            free(message);

            if (strstr(server_response, "error")) {
                puts ("You have no access to the library.");
                free(server_response);
                close(sock_tcp);
                continue;
            }

            /* initialize JSON Object to get the array from server_response */
            char *p = strstr(server_response, "[");
            JSON_Value *big_json = json_parse_string(p);
            if (json_value_get_type(big_json) != JSONArray) {
                free(server_response);
                close(sock_tcp);
                json_value_free(big_json);
                continue;
            }

            /* display the books */
            JSON_Array *books = json_value_get_array(big_json);

            if (json_array_get_count(books) == 0)
                puts("There are currently no books, try adding one.");
            else {
                puts("ID -- TITLE");
                for (size_t i = 0; i < json_array_get_count(books); i++) {
                    JSON_Object *book = json_array_get_object(books, i);
                    printf("id: %d -- title: %s\n", (int)json_object_get_number(book, "id"), json_object_get_string(book, "title"));
                }
            }

            json_value_free(big_json);
            free(server_response);
            close(sock_tcp);
        }
        else if (!strcmp(stdin_buffer, "get_book")) {

            if (cookie == NULL) {
                puts("No user is logged in.");
                continue;
            }

            sock_tcp = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

            memset(username, 0, BUFLEN);
            printf("id=");
            getline(&username, &buflen, stdin);
            remove_newline(username);

            memset(access_route, 0, BUFLEN);
            sprintf(access_route, "/api/v1/tema/library/books/%s", username);

            /* compute get request */
            message = compute_get_delete_request(HOST, access_route, NULL, cookie, jwt, "GET");

            /* send the message to server */
            send_to_server(sock_tcp, message);
            server_response = receive_from_server(sock_tcp);
            free(message);

            /* Either the id was not a number or there is no book with that id */
            if (strstr(server_response, "error")) {
                printf("There is no book with id %s.\n", username);
                free(server_response);
                close(sock_tcp);
                continue;
            }

            /* initialize JSON Object */
            char *p = strstr(server_response, "{");
            JSON_Value *big_json = json_parse_string(p);
            if (json_value_get_type(big_json) != JSONObject) {
                json_value_free(big_json);
                close(sock_tcp);
                free(server_response);
                continue;
            }

            /* display all the info about the book */
            JSON_Object *book = json_value_get_object(big_json);
            printf("id: %d\n", (int)json_object_get_number(book, "id"));
            printf("title: %s\n", json_object_get_string(book, "title"));
            printf("author: %s\n", json_object_get_string(book, "author"));
            printf("publisher: %s\n", json_object_get_string(book, "publisher"));
            printf("genre: %s\n", json_object_get_string(book, "genre"));
            printf("page_count: %d\n", (int)json_object_get_number(book, "page_count"));

            free(server_response);
            json_value_free(big_json);
            close(sock_tcp);
        }
        else if (!strcmp(stdin_buffer, "delete_book")) {

            if (cookie == NULL) {
                puts("No user is logged in.");
                continue;
            }

            sock_tcp = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

            memset(username, 0, BUFLEN);
            printf("id=");
            getline(&username, &buflen, stdin);
            remove_newline(username);

            memset(access_route, 0, BUFLEN);
            sprintf(access_route, "/api/v1/tema/library/books/%s", username);

            /* compute get request */
            message = compute_get_delete_request(HOST, access_route, NULL, cookie, jwt, "DELETE");

            /* send the message to server */
            send_to_server(sock_tcp, message);
            server_response = receive_from_server(sock_tcp);
            free(message);

            if (strstr(server_response, "error")) {
                printf("There is no book with id %s.\n", username);
                free(server_response);
                close(sock_tcp);
                continue;
            }
            puts("200 - OK - Successfully deleted book.");

            free(server_response);
            close(sock_tcp);
        }
        else if (!strcmp(stdin_buffer, "add_book")) {

            if (cookie == NULL) {
                puts("No user is logged in.");
                continue;
            }
            sock_tcp = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

            /* put access route */
            memset(access_route, 0, BUFLEN);
            sprintf(access_route, "/api/v1/tema/library/books");

            /* put payload type */
            memset(payload_type,0, BUFLEN);
            sprintf(payload_type, "application/json");

            /* initialize JSON Object */
            JSON_Value *big_json = json_value_init_object();
            JSON_Object *book_object = json_value_get_object(big_json);

            /* read inputs from stdin and save the info in a json */
            memset(general_use_buffer, 0, BUFLEN);
            printf("title=");
            getline(&general_use_buffer, &buflen, stdin);
            remove_newline(general_use_buffer);
            json_object_set_string(book_object, "title", general_use_buffer);

            memset(general_use_buffer, 0, BUFLEN);
            printf("author=");
            getline(&general_use_buffer, &buflen, stdin);
            remove_newline(general_use_buffer);
            json_object_set_string(book_object, "author", general_use_buffer);

            memset(general_use_buffer, 0, BUFLEN);
            printf("genre=");
            getline(&general_use_buffer, &buflen, stdin);
            remove_newline(general_use_buffer);
            json_object_set_string(book_object, "genre", general_use_buffer);

            memset(general_use_buffer, 0, BUFLEN);
            printf("publisher=");
            getline(&general_use_buffer, &buflen, stdin);
            remove_newline(general_use_buffer);

            memset(username, 0, BUFLEN);
            printf("page_count=");
            getline(&username, &buflen, stdin);
            remove_newline(username);
            
            /* check if the input for page count is valid */
            if (!check_number(username)) {
                puts("Wrong input for page_count, try again.");
                json_value_free(big_json);
                close(sock_tcp);
                continue;
            }

            json_object_set_number(book_object, "page_count", atoi(username));
            json_object_set_string(book_object, "publisher", general_use_buffer);

            char *data = json_serialize_to_string(big_json);

            /* compute post request */
            message = compute_post_request(HOST, access_route, payload_type, &data, strlen(data), cookie, jwt);
            free(data);

            /* send the message to server */
            send_to_server(sock_tcp, message);
            server_response = receive_from_server(sock_tcp);
            free(message);

            /* check for errors */
            if (strstr(server_response, "error"))
                puts("Couldn't add the book, try again.");
            else
                puts("200 - OK - Book added successfully.");

            json_value_free(big_json);
            free(server_response);
            close(sock_tcp);
        }
        else if (!strcmp(stdin_buffer, "logout")) {
            if (cookie == NULL) {
                puts("No user is logged in.");
                continue;
            }
            sock_tcp = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

            /* put access route */
            memset(access_route, 0, BUFLEN);
            sprintf(access_route, "/api/v1/tema/auth/logout");

            /*compute get request*/
            message = compute_get_delete_request(HOST, access_route, NULL, cookie, NULL, "GET");

            /* send the message to server */
            send_to_server(sock_tcp, message);
            server_response = receive_from_server(sock_tcp);
            free(message);

            if (strstr(server_response, "error")) {
                puts("Couldn't log out.");
                free(server_response);
                close(sock_tcp);
                continue;
            }
            
            puts("200 - OK - User logged out.");

            /* The session is over, mark the session as free to use for another user */
            free(cookie);
            cookie = NULL;
            free(jwt);
            jwt = NULL;
            free(server_response);
            close(sock_tcp);
        }
        else if (!strcmp(stdin_buffer, "exit")) {

            /* memory release */
            if (cookie != NULL)
                free(cookie);
            if (jwt != NULL)
                free(jwt);
            free(stdin_buffer);
            free(access_route);
            free(payload_type);
            free(username);
            free(password);
            free(general_use_buffer);
            break;
        } else {

            /* the user entered a different command from the ones accepted */
            puts("Wrong command.");
        }
    }

    return 0;
}