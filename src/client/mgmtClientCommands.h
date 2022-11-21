
#ifndef MGMT_CLIENT_CMDS_H

#define MGMT_CLIENT_CMDS_H


int cmdUsers(int sock, int cmdValue);

int cmdAddUser(int sock, int cmdValue, char* username, char* password, char* role);

int cmdDeleteUser(int sock, int cmdValue, char * username);

int cmdChangePassword(int sock, int cmdValue, char * username, char * password);

int cmdChangeRole(int sock, int cmdValue, char * username, char * role);

int cmdGetDissectorStatus(int sock, int cmdValue);

int cmdSetDissectorStatus(int sock, int cmdValue, char * status);

int cmdGetAuthenticationStatus(int sock, int cmdValue);

int cmdSetAuthenticationStatus(int sock, int cmdValue, char * status);

int cmdStats(int sock, int cmdValue);

#endif
