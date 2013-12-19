/* For sockaddr_in */
#include <netinet/in.h>
/* For socket functions */
#include <sys/socket.h>
#include <sys/un.h>
/* For fcntl */
#include <fcntl.h>
#include <event2/event.h>

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>

#define MAX_LINE 16384

void do_read(evutil_socket_t fd, short events, void *arg);
void do_write(evutil_socket_t fd, short events, void *arg);
extern void route_server(int client, char *ibuf, int len);

struct fd_state {
        char buffer[MAX_LINE];
        size_t buffer_used;

        size_t n_written;
        size_t write_upto;

        struct event *read_event;
        struct event *write_event;
};

struct fd_state* alloc_fd_state(struct event_base *base, evutil_socket_t fd) {
        struct fd_state *state = malloc(sizeof(struct fd_state));
        if (!state)
                return NULL;
        state->read_event = event_new(base, fd, EV_READ|EV_PERSIST,
                        do_read, state
                        );
        if (!state->read_event) {
                free(state);
                return NULL;
        }
        /*
        state->write_event =
                event_new(base, fd, EV_WRITE|EV_PERSIST, do_write, state);

        if (!state->write_event) {
                event_free(state->read_event);
                free(state);
                return NULL;
        }
        */

        state->buffer_used = state->n_written = state->write_upto = 0;

        //assert(state->write_event);
        return state;
}

void free_fd_state(struct fd_state *state)
{
        event_free(state->read_event);
//        event_free(state->write_event);
        free(state);
}

void do_read(evutil_socket_t fd, short events, void *arg)
{
        struct fd_state *state = arg;
        int i;
        ssize_t result;
        while (1) {
                result = recv(fd, state->buffer+state->buffer_used,
                                sizeof(state->buffer)-state->buffer_used,
                                0
                                );
                if(result <= 0)
                        break;
                state->buffer_used += result;
                i = state->buffer_used;
                if(('\n'==state->buffer[i-1]) &&
                    ('\n'==state->buffer[i-2])) {
                        route_server(fd, state->buffer, i-2);
                        fprintf(stderr, "close client\n");
                        //close(fd);
                        shutdown(fd, SHUT_RDWR);
                        close(fd);
                        //evutil_closesocket(fd);
                        free_fd_state(state);
                        return;
                }
        }

        if (result == 0) {
                free_fd_state(state);
        } else if (result < 0) {
                if (errno == EAGAIN) // XXXX use evutil macro
                        return;
                perror("recv");
                free_fd_state(state);
        }
}

void do_write(evutil_socket_t fd, short events, void *arg)
{
        struct fd_state *state = arg;

        while (state->n_written < state->write_upto) {
                ssize_t result = send(fd, state->buffer + state->n_written,
                                      state->write_upto - state->n_written, 0);
                if (result < 0) {
                        if (errno == EAGAIN) // XXX use evutil macro
                                return;
                        free_fd_state(state);
                        return;
                }
                assert(result != 0);

                state->n_written += result;
        }

        if (state->n_written == state->buffer_used)
                state->n_written = state->write_upto = state->buffer_used = 1;

        event_del(state->write_event);
}

void do_accept(evutil_socket_t listener, short event, void *arg)
{
        struct event_base *base = arg;
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int fd = accept(listener, (struct sockaddr*)&ss, &slen);
        if (fd < 0) { // XXXX eagain??
                perror("accept");
        } else if (fd > FD_SETSIZE) {
                close(fd); // XXX replace all closes with EVUTIL_CLOSESOCKET */
        } else {
                struct fd_state *state;
                evutil_make_socket_nonblocking(fd);
                state = alloc_fd_state(base, fd);
                assert(state); /*XXX err*/
                //assert(state->write_event);
                event_add(state->read_event, NULL);
                printf("Client fd:%d\n", fd);
        }
}

void run(void)
{
        evutil_socket_t listener;
        struct sockaddr_un sin;
        struct event_base *base;
        struct event *listener_event;
        int one=1, len=0;

        base = event_base_new();
        if (!base)
                return; /*XXXerr*/

        bzero(&sin, sizeof(sin));
        sin.sun_family = AF_UNIX;
        strcpy(sin.sun_path, "/tmp/route");
        len = offsetof(struct sockaddr_un, sun_path) + strlen("/tmp/route");
        unlink("/tmp/route");

        listener = socket(AF_UNIX, SOCK_STREAM, 0);
        evutil_make_socket_nonblocking(listener);
        evutil_make_socket_closeonexec(listener);
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        if (bind(listener, (struct sockaddr*)&sin, len) < 0) {
                perror("bind");
                return;
        }

        if (listen(listener, 16)<0) {
                perror("listen");
                return;
        }

        listener_event = event_new(base, listener,
                        EV_READ|EV_PERSIST, do_accept, (void*)base);
        /*XXX check it */
        event_add(listener_event, NULL);

        event_base_dispatch(base);
}

int main(int argc, char **argv)
{
        init_shm();
        setvbuf(stdout, NULL, _IONBF, 0);

        run();
        return 0;
}
