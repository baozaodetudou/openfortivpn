#include "manager_control.h"
#include "event.h"
#include "tunnel.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <unistd.h>
#endif

#ifndef _WIN32
static void *apply_native(void *context)
{
    manager_control_network_apply(context);
    pthread_testcancel();
    return NULL;
}
#endif

int main(int argc, char **argv)
{
    char response[64],line[5000];
    const char *attempt="00000000-0000-4000-8000-000000000001";
    const char *nonce="0123456789abcdef0123456789abcdef";
    assert(manager_control_init("invalid") == -1);
    assert(manager_control_init(attempt) == 0);
#ifndef _WIN32
    if (argc == 2 && strcmp(argv[1], "launch") == 0) {
        assert(manager_launch_init("0") == -1);
        assert(manager_launch_init("-3") == -1);
        assert(manager_launch_init("3x") == -1);
        if (manager_launch_init("3") != 0) return 2;
        assert(manager_launch_init("3") == -1);
        return manager_launch_wait() == 0 ? 0 : 2;
    }
#endif
    if (argc == 2) {
        int result;
        event_init(1);
        if (strcmp(argv[1],"otp")==0) {
            result=manager_control_otp("Synthetic token challenge",response,sizeof(response));
            if (result == 0) assert(strcmp(response,"synthetic-otp")==0);
        }
#ifndef _WIN32
        else if (strcmp(argv[1],"native")==0 || strcmp(argv[1],"native-unsafe")==0 || strcmp(argv[1],"native-proxy-route")==0 || strcmp(argv[1],"native-cancel")==0) {
            struct vpn_config config = {0};
            struct tunnel tunnel = {0};
            struct rtentry route = {0};
            int listener = socket(AF_INET,SOCK_STREAM,0);
            struct sockaddr_in address = {0};
            socklen_t length = sizeof(address);
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            assert(listener >= 0 && bind(listener,(struct sockaddr *)&address,sizeof(address)) == 0);
            assert(getsockname(listener,(struct sockaddr *)&address,&length) == 0 && listen(listener,1) == 0);
            tunnel.ssl_socket = socket(AF_INET,SOCK_STREAM,0);
            assert(tunnel.ssl_socket >= 0 && connect(tunnel.ssl_socket,(struct sockaddr *)&address,sizeof(address)) == 0);
            int accepted = accept(listener,NULL,NULL);
            assert(accepted >= 0);
            tunnel.config = &config;
            config.set_routes = 1;
            config.gateway_ip.s_addr = inet_addr("192.0.2.9");
#ifdef __linux__
            strcpy(tunnel.ppp_iface,"lo");
#else
            strcpy(tunnel.ppp_iface,"lo0");
#endif
            tunnel.ipv4.ip_addr.s_addr = inet_addr("127.0.0.1");
            tunnel.ipv4.split_rt = &route;
            tunnel.ipv4.split_routes = 1;
            route_dest(&route).s_addr = inet_addr(strcmp(argv[1],"native-proxy-route")==0 ? "127.0.0.0" : "10.0.0.0");
            route_mask(&route).s_addr = inet_addr(strcmp(argv[1],"native-unsafe")==0 ? "0.0.0.0" : "255.0.0.0");
            if (strcmp(argv[1],"native-cancel")==0) {
                pthread_t worker;
                void *exit_status;
                assert(pthread_create(&worker,NULL,apply_native,&tunnel)==0);
                usleep(50000);
                assert(pthread_cancel(worker)==0);
                assert(pthread_join(worker,&exit_status)==0 && exit_status==PTHREAD_CANCELED);
                result=0;
            } else result=manager_control_network_apply(&tunnel);
            if (result == 0) result=manager_control_network_release(&tunnel);
            close(accepted); close(tunnel.ssl_socket); close(listener);
        }
#endif
        else {
            struct vpn_config config = {0};
            struct tunnel tunnel = {0};
            tunnel.config = &config;
            result=manager_control_network_gate(&tunnel);
        }
        return result == 0 ? 0 : 2;
    }
    assert(manager_control_enabled());
    snprintf(line,sizeof(line),"OFV2 %s %s auth_response c3ludGhldGljLW90cA==",attempt,nonce);
    assert(manager_control_decode(line,nonce,"auth_response",response,sizeof(response)) == 0);
    assert(strcmp(response,"synthetic-otp") == 0);
    assert(manager_control_decode(line,"different-nonce","auth_response",response,sizeof(response)) == -1);
    assert(response[0] == '\0');
    assert(manager_control_decode(line,nonce,"lease_decision",response,sizeof(response)) == -1);
    assert(manager_control_decode(line,nonce,"auth_response",response,4) == -1);
    snprintf(line,sizeof(line),"OFV2 %s %s auth_response AA==",attempt,nonce);
    assert(manager_control_decode(line,nonce,"auth_response",response,sizeof(response)) == -1);
    snprintf(line,sizeof(line),"OFV2 %s %s auth_response YQo=",attempt,nonce);
    assert(manager_control_decode(line,nonce,"auth_response",response,sizeof(response)) == -1);
    snprintf(line,sizeof(line),"OFV2 %s %s auth_response Zh==",attempt,nonce);
    assert(manager_control_decode(line,nonce,"auth_response",response,sizeof(response)) == -1);
    snprintf(line,sizeof(line),"OFV2 %s %s lease_decision Z3JhbnQ=",attempt,nonce);
    assert(manager_control_decode(line,nonce,"lease_decision",response,sizeof(response)) == 0);
    assert(strcmp(response,"grant") == 0);
    assert(manager_control_init("00000000-0000-4000-8000-000000000002") == 0);
    assert(manager_control_decode(line,nonce,"lease_decision",response,sizeof(response)) == -1);
    puts("Manager control identity, replay, bounds and secret framing checks passed");
    return 0;
}
