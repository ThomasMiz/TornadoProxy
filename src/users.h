#ifndef _USERS_H_
#define _USERS_H_

#include <stdbool.h>
#include "selector.h"

/** The maximum length of a user's username. */
#define USERS_MAX_USERNAME_LENGTH 31
/** The maximum length of a user's password. */
#define USERS_MAX_PASSWORD_LENGTH 31

/** The file on disk to which user data is saved. */
#define USERS_DEFAULT_FILE "users.txt"

/* The users file has a simple text format so it can be easily modified in a text editor by the
 * server administrator.
 * Each line contains the data about a single user. First, a character indicating the level of
 * privilege. '@' for admin, '#' for user. This is followed by the username, followed by a ':',
 * followed by the password.
 * The order in which the users are specified is irrelevant.
 *
 * Example of how a users file would look if it had four users; an admin named "admin" with password
 * "1234", a user named "user" with no password, an admin named "pedro_el_grande" with password
 * "gomero", and another user named "pedro_el_chico" with password "4321":
@admin:1234
#user:
@pedro_el_grande:gomero
#pedro_el_chico:4321
*/

/** The maximum amount of users the system supports. */
#define USERS_MAX_COUNT 100

/** When no users are present, a default admin user is created with this name and password */
#define USERS_DEFAULT_USERNAME "admin"
#define USERS_DEFAULT_PASSWORD "admin"

/** A regex used for username validation, independent of string length. */
#define USERS_USERNAME_REGEX "^[a-zA-Z][a-zA-Z0-9_\\-ñ]*$"
/** A regex used for password validation, independent of string length. */
#define USERS_PASSWORD_REGEX "^[ -9;-~]*$"
// The password can contain any ASCII char between 32 (' ') and 126 ('~'), except for ':'.

/**
 * Represents a user's privilege level.
 */
typedef enum {
    UPRIV_USER = 0,
    UPRIV_ADMIN = 1
} TUserPrivilegeLevel;

/**
 * Defines the possible status codes returned by functions from the users module.
 */
typedef enum {
    EUSER_OK = 0,
    EUSER_WRONGUSERNAME = 1,
    EUSER_ALREADYEXISTS = 2,
    EUSER_WRONGPASSWORD = 3,
    EUSER_LIMITREACHED = 4,
    EUSER_CREDTOOLONG = 5,
    EUSER_BADUSERNAME = 6,
    EUSER_BADPASSWORD = 7,
    EUSER_BADOPERATION = 8,
    EUSER_NOMEMORY = 9,
    EUSER_UNKNOWNERROR = -1,
} TUserStatus;

/**
 * @brief Initializes the users system.
 * @param usersFile The file in disk in which to load and store user data. Set to NULL or an
 * empty string to use the default users file.
 */
int usersInit(const char* usersFile);

/**
 * @brief Checks whether a given username exists and verifies that it's password matches.
 * @param username The username of the user to check.
 * @param password The password of the user to check. An empty or null password is taken as a
 * "the user has no password".
 * @param outLevel A pointer to a variable where the user's privilege level will be written to.
 * @returns A value from TUserStatus. Either OK, WRONGUSERNAME, or WRONGPASSWORD.
 */
TUserStatus usersLogin(const char* username, const char* password, TUserPrivilegeLevel* outLevel);

/**
 * @brief Creates a user with the given username and password, or updates an existing user's
 * password or privilege level.
 * @param username The username for the user.
 * @param password The password for the user. An empty or null password is taken as a "the user
 * has no password".
 * @param updatePassword Whether to update the password if the user already exists.
 * @param privilege The privilege level for the user.
 * @param updatePrivilege Whether to update the user's privilege level if the user already exists.
 * @returns A value from TUserStatus. Either OK, ALREADYEXISTS, CREDTOOLONG, BADUSERNAME,
 * BADPASSWORD, LIMITREACHED, NOMEMORY, or BADOPERATION (if downgrading privileges from last
 * admin in the system).
 */
TUserStatus usersCreate(const char* username, const char* password, bool updatePassword, TUserPrivilegeLevel privilege, bool updatePrivilege);

/**
 * @brief Deletes a user from the system.
 * @param username The username of the user to delete.
 * @returns A value from TUserStatus. Either OK, WRONGUSERNAME, or BADOPERATION (if the user is
 * the last administrator on the system).
 */
TUserStatus usersDelete(const char* username);

/**
 * @brief Shuts down the user system, flushing the users to a file on disk.
 */
TUserStatus usersFinalize();

/**
 * @brief Returns a const string with a human-readable representation of a given user privilige level.
*/
const char* usersPrivilegeToString(TUserPrivilegeLevel privilege);

/**
 * @brief Returns true if a user already exists
 */
bool userExists(const char * username);

#endif
