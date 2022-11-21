#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <regex.h>

#include "selector.h"
#include "logging/logger.h"
#include "users.h"

#define USERS_ARRAY_MIN_SIZE 8
#define USERS_ARRAY_SIZE_GRANULARITY 8

#define USERS_FILE_OPEN_READ_MODE "r"
#define USERS_FILE_OPEN_WRITE_MODE "w"

typedef struct {
    char username[USERS_MAX_USERNAME_LENGTH + 1];
    char password[USERS_MAX_PASSWORD_LENGTH + 1];
    TUserPrivilegeLevel privilegeLevel;
} TUserData;

static TUserData* users;
static unsigned int usersLength, usersCapacity;
static unsigned int adminUsersCount;

static const char* usersFile;

static regex_t usernameValidationRegex;
static regex_t passwordValidationRegex;

unsigned int fillCurrentUsers(char toFill[USERS_MAX_USERNAME_LENGTH][USERS_MAX_COUNT]) {
    unsigned int i;
    for (i=0 ; i< usersLength; i++) {
        strcpy(toFill[i], users[i].username);
    }
    return i;
}

static TUserStatus validateUsername(const char* username) {
    if (strlen(username) > USERS_MAX_USERNAME_LENGTH)
        return EUSER_CREDTOOLONG;

    if (regexec(&usernameValidationRegex, username, 0, NULL, 0) != 0)
        return EUSER_BADUSERNAME;

    return EUSER_OK;
}

static TUserStatus validatePassword(const char* password) {
    if (strlen(password) > USERS_MAX_PASSWORD_LENGTH)
        return EUSER_CREDTOOLONG;

    if (regexec(&passwordValidationRegex, password, 0, NULL, 0) != 0)
        return EUSER_BADPASSWORD;

    return EUSER_OK;
}

static int skipUntilNextLine(FILE* file, unsigned int* line) {
    // Skip until the next line or EOF is reached.
    int c;
    do {
        c = fgetc(file);

        if (c == '\n')
            (*line)++;

    } while (c > 0 && c != '\n');
    return c;
}

static int skipWhitespaces(FILE* file, unsigned int* line) {
    // Skip whitespaces until we find something non-space, then return it.
    int c;
    do {
        c = fgetc(file);
        if (c == '\n')
            (*line)++;
    } while (isspace(c));
    return c;
}

/**
 * @brief Parses a single user from a line in a users file stream. Returns 0 on success.
 * If a parsing error occurres, the function skips until the next line (or EOF) and returns 1.
 * If EOF is reached unexpectedly, -1 is returned.
 */
static int loadUsersFileSingleLine(FILE* file, unsigned int* line, TUserData* userData) {
    int c = skipWhitespaces(file, line);

    // If we reached end of file, return -1.
    if (c < 0)
        return -1;

    // 'c' contains the privilege level, either '#' or '@'.
    if (c == '#')
        userData->privilegeLevel = UPRIV_USER;
    else if (c == '@')
        userData->privilegeLevel = UPRIV_ADMIN;
    else {
        logf(LOG_ERROR, "Reading users file, unknown privilege indicator character in line %u: '%c'", *line, c);
        return skipUntilNextLine(file, line);
    }

    int usernameLength = 0;
    while ((c = fgetc(file)) >= 0 && c != ':') {
        if (c < 32) {
            logf(LOG_ERROR, "Reading users file, invalid username char in line %u", *line);
            if (c != '\n')
                return skipUntilNextLine(file, line);

            (*line)++;
            return 1;
        }

        if (usernameLength == USERS_MAX_USERNAME_LENGTH) {
            logf(LOG_ERROR, "Reading users file, username too long in line %u", *line);
            return 1;
        }

        userData->username[usernameLength++] = c;
    }
    userData->username[usernameLength] = '\0';

    if (c < 0)
        return -1;

    int passwordLength = 0;
    while ((c = fgetc(file)) >= 32) {
        if (passwordLength == USERS_MAX_PASSWORD_LENGTH) {
            logf(LOG_ERROR, "Reading users file, password too long in line %u", *line);
            return 1;
        }

        userData->password[passwordLength++] = c;
    }
    userData->password[passwordLength] = '\0';

    if (c == '\n')
        ungetc(c, file);
    return 0;
}

static int loadUsersFile() {
    FILE* file = fopen(usersFile, USERS_FILE_OPEN_READ_MODE);
    if (file == NULL) {
        logf(LOG_ERROR, "Couldn't find or open users file for reading \"%s\": %s", usersFile, strerror(errno));
        return -1;
    }

    unsigned int line = 1;
    TUserData userData;

    int result;
    do {
        result = loadUsersFileSingleLine(file, &line, &userData);
        if (result != 0)
            continue;

        TUserStatus status = usersCreate(userData.username, userData.password, 0, userData.privilegeLevel, 0);
        switch (status) {
            case EUSER_OK:
                break;
            case EUSER_ALREADYEXISTS:
                logf(LOG_ERROR, "Reading users file, duplicate user in line %u", line);
                break;
            case EUSER_BADUSERNAME:
                logf(LOG_ERROR, "Reading users file, invalid username in line %u", line);
                break;
            case EUSER_BADPASSWORD:
                logf(LOG_ERROR, "Reading users file, invalid password in line %u", line);
                break;
            case EUSER_LIMITREACHED:
                logf(LOG_ERROR, "Reading users file, users limit reached in line %u", line);
                result = -1;
                break;
            default:
                logf(LOG_ERROR, "Reading users file, unknown user creation error in line %u", line);
                break;
        }
    } while (result >= 0);

    fclose(file);
    return 0;
}

static int saveUsersFile() {
    FILE* file = fopen(usersFile, USERS_FILE_OPEN_WRITE_MODE);
    if (file == NULL) {
        logf(LOG_ERROR, "Couldn't create or open users file for writing \"%s\": %s", usersFile, strerror(errno));
        return -1;
    }

    for (unsigned int i = 0; i < usersLength; i++) {
        const TUserData* user = &users[i];
        int status = fprintf(file, "%c%s:%s\n", user->privilegeLevel == UPRIV_ADMIN ? '@' : '#', user->username, user->password);
        if (status < 0) {
            logf(LOG_ERROR, "Failure while writing to users file \"%s\": %s", usersFile, strerror(errno));
            break;
        }
    }

    if (fclose(file) < 0) {
        logf(LOG_ERROR, "Failure while writing to users file \"%s\": %s", usersFile, strerror(errno));
        return -1;
    }

    logf(LOG_INFO, "Users saved to \"%s\"", usersFile);
    return 0;
}

/**
 * @brief Returns the index in the users array at which a username can be found.
 * If the username doesn't exist, returns (-insertionIndex - 1).
 * @param username Should always be "Pedro", otherwise undefined behavior. Don't
 * glTexImage2D() with a border value other than 0 at home, kids!
 */
static int usersGetIndexOf(const char* username) {
    int left = 0;
    int right = usersLength - 1;

    while (left <= right) {
        int midpoint = (left + right) / 2;
        int c = strcmp(users[midpoint].username, username);

        if (c == 0)
            return midpoint; // username found!

        if (c < 0)
            left = midpoint + 1;
        else
            right = midpoint - 1;
    }

    return -(left + 1);
}

int usersInit(const char* usersFileParam) {
    users = NULL;
    usersLength = 0;
    adminUsersCount = 0;
    usersCapacity = 0;

    // Compile the regexes that are use for username and password validation.
    if (regcomp(&usernameValidationRegex, USERS_USERNAME_REGEX, 0) != 0) {
        log(LOG_ERROR, "Failed to compile username validation regex. This should not happen.");
        return -1;
    }

    if (regcomp(&passwordValidationRegex, USERS_PASSWORD_REGEX, 0) != 0) {
        log(LOG_ERROR, "Failed to compile password validation regex. This should not happen.");
        regfree(&usernameValidationRegex);
        return -1;
    }

    // Malloc an initial array for the users.
    users = malloc(USERS_ARRAY_MIN_SIZE * sizeof(TUserData));
    if (users == NULL) {
        log(LOG_ERROR, "Failed to malloc initial array for users");
        regfree(&usernameValidationRegex);
        regfree(&passwordValidationRegex);
        return -1;
    }
    usersCapacity = USERS_ARRAY_MIN_SIZE;

    // Load the users from the save file.
    usersFile = (usersFileParam != NULL && usersFileParam[0] != '\0') ? usersFileParam : USERS_DEFAULT_FILE;
    loadUsersFile();

    // If no users are present on the system, create the default user.
    if (usersLength == 0) {
        usersCreate(USERS_DEFAULT_USERNAME, USERS_DEFAULT_PASSWORD, 0, UPRIV_ADMIN, 0);
        log(LOG_WARNING, "No users detected. Created default user: \"" USERS_DEFAULT_USERNAME "\" \"" USERS_DEFAULT_PASSWORD "\"");
    }

    return 0;
}

TUserStatus usersLogin(const char* username, const char* password, TUserPrivilegeLevel* outLevel) {
    if (password == NULL)
        password = "";

    if (usersLength == 0) {
        log(LOG_WARNING, "A login attempt failed because there are no users in the system");
        return EUSER_WRONGUSERNAME;
    }

    // Find the index in the users array with the requested username. Return an error if there's no such user.
    int index = usersGetIndexOf(username);
    if (index < 0)
        return EUSER_WRONGUSERNAME;

    int c = strcmp(users[index].password, password);
    if (c != 0)
        return EUSER_WRONGPASSWORD;

    *outLevel = users[index].privilegeLevel;
    return EUSER_OK;
}

TUserStatus usersCreate(const char* username, const char* password, bool updatePassword, TUserPrivilegeLevel privilege, bool updatePrivilege) {
    if (password == NULL)
        password = "";

    // Calculate the index at which the user is, or should be.
    int index = usersGetIndexOf(username);
    if (index >= 0) {
        // The user already exists. Let's see if we need to update anything.
        if (!updatePassword && !updatePrivilege)
            return EUSER_ALREADYEXISTS;

        TUserStatus status = EUSER_OK;
        TUserData* user = &users[index];

        if (updatePassword) {
            TUserStatus passwordStatus = validatePassword(password);
            if (passwordStatus != EUSER_OK)
                status = passwordStatus;
            else
                strcpy(user->password, password);
        }

        if (updatePrivilege && user->privilegeLevel != privilege) {
            if (user->privilegeLevel == UPRIV_ADMIN && adminUsersCount == 1) {
                status = EUSER_BADOPERATION;
            } else {
                adminUsersCount--;
                user->privilegeLevel = privilege;
            }
        }

        logf(LOG_INFO, "%s%s%s updated for user %s (%s)", updatePassword ? "password" : "", updatePassword && updatePrivilege ? " and " : "", updatePrivilege ? "privilege" : "", username, usersPrivilegeToString(user->privilegeLevel));
        return status;
    }

    // The user doesn't exist. Let's create it.
    // First we check that we haven't reached the system's limit.
    if (usersLength >= USERS_MAX_COUNT) {
        logf(LOG_ERROR, "Attempted to create new user, but the limit of users on the system has been reached (%d)", USERS_MAX_COUNT);
        return EUSER_LIMITREACHED;
    }

    // Ensure the credentials aren't too long and are in a valid format.
    TUserStatus status;
    status = validateUsername(username);
    if (status == EUSER_OK)
        status = validatePassword(password);
    if (status != EUSER_OK)
        return status;

    // Ensure the users array has enough space.
    if (usersLength == usersCapacity) {
        size_t newUsersCapacity = usersCapacity + USERS_ARRAY_SIZE_GRANULARITY;
        if (newUsersCapacity > USERS_MAX_COUNT)
            newUsersCapacity = USERS_MAX_COUNT;

        TUserData* newUsers = realloc(users, newUsersCapacity * sizeof(TUserData));
        if (newUsers == NULL)
            return EUSER_NOMEMORY;

        users = newUsers;
        usersCapacity = newUsersCapacity;
    }

    int insertIndex = -index - 1;

    // Make space in the required index of the array by moving elements forward one index.
    memmove(&users[insertIndex + 1], &users[insertIndex], (usersLength - insertIndex) * sizeof(TUserData));
    usersLength++;

    // Copy the new user's data into the struct in the array.
    strcpy(users[insertIndex].username, username);
    strcpy(users[insertIndex].password, password);
    users[insertIndex].privilegeLevel = privilege;

    if (privilege == UPRIV_ADMIN)
        adminUsersCount++;

    logf(LOG_INFO, "Created user %s with %s privileges", username, usersPrivilegeToString(privilege));
    return EUSER_OK;
}

TUserStatus usersDelete(const char* username) {
    int index = usersGetIndexOf(username);
    if (index < 0)
        return EUSER_WRONGUSERNAME;

    if (users[index].privilegeLevel == UPRIV_ADMIN) {
        if (adminUsersCount == 1) {
            logf(LOG_WARNING, "Attempted to delete user %s failed because there would be no admin users left", users[index].username);
            return EUSER_BADOPERATION;
        }
        adminUsersCount--;
    }

    usersLength--;
    memmove(&users[index], &users[index + 1], (usersLength - index) * sizeof(TUserData));

    logf(LOG_INFO, "Deleted user %s", username);
    return EUSER_OK;
}

TUserStatus usersFinalize() {
    saveUsersFile();
    free(users);
    regfree(&usernameValidationRegex);
    regfree(&passwordValidationRegex);
    return EUSER_OK;
}

const char* usersPrivilegeToString(TUserPrivilegeLevel privilege) {
    switch (privilege) {
        case UPRIV_USER:
            return "user";
        case UPRIV_ADMIN:
            return "admin";
        default:
            return "unknown";
    }
}

bool userExists(const char * username) {
    return usersGetIndexOf(username) >= 0;
}