#ifndef _USERS_H_
#define _USERS_H_

#define MAX_USERNAME_LENGTH 31
#define MAX_PASSWORD_LENGTH 31

#define DEFAULT_USERS_FILE "users.txt"

#include "selector.h"

/**
 * @brief Initializes the users system.
 * @param selector The selector to use. This is requried in order to write to the
 * users file with non-blocking calls.
 * @param usersFile The file in disk in which to load and store user data. Set to
 * NULL or an empty string to use the default users file.
*/
int usersInit(TSelector selector, const char* usersFile);

/**
 * @brief Checks whether a given username exists and verifies that it's password
 * matches.
 * @param username The username of the user to check.
 * @param password The password of the user to check.
 * @returns 0 if the user exists and the password matches. 1 if the user exists,
 * but the password doesn't match, or 2 if the username doesn't exist.
*/
int usersLogin(const char* username, const char* password);

/**
 * @brief Creates a user with the given username and password.
 * @param username The username to give the new user.
 * @param password The password to give the new user.
 * @param updatePassword Whether to update the password if the user already exists.
 * @returns 0 if the user was created successfully, 1 if the user already exists,
 * or -1 for other unspecified errors.
*/
int usersCreate(const char* username, const char* password, int updatePassword);

/**
 * @brief Shuts down the user system, ensuring any remaining data on memory is
 * flushed to disk.
*/
int usersFinalize();

#endif