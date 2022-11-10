#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <regex.h>

#include "selector.h"
#include "users.h"

#define USERS_ARRAY_MIN_SIZE 8
#define USERS_ARRAY_SIZE_GRANULARITY 8

#define USERS_FILE_PERMISSION_BITS 666
#define USERS_FILE_OPEN_FLAGS (O_WRONLY | O_CREAT | O_TRUNC)

typedef struct {
    char username[USERS_MAX_USERNAME_LENGTH + 1];
    char password[USERS_MAX_PASSWORD_LENGTH + 1];
    TUserPriviligeLevel priviligeLevel;
} TUserData;

static TUserData* users;
static unsigned int usersLength, usersCapacity;
static unsigned int adminUsersCount;

static const char* usersFile;

static regex_t usernameValidationRegex;
static regex_t passwordValidationRegex;

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

static int loadUsersFile() {
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

    return -(left + 1); // username not found 💀
}

int usersInit(const char* usersFileParam) {
    users = NULL;
    usersLength = 0;
    adminUsersCount = 0;
    usersCapacity = 0;

    if (regcomp(&usernameValidationRegex, USERS_USERNAME_REGEX, 0) != 0) {
        fprintf(stderr, "ERROR: Failed to compile username validation regex. This should not happen.\n");
        return -1;
    }

    if (regcomp(&passwordValidationRegex, USERS_PASSWORD_REGEX, 0) != 0) {
        fprintf(stderr, "ERROR: Failed to compile password validation regex. This should not happen.\n");
        regfree(&usernameValidationRegex);
        return -1;
    }

    users = malloc(USERS_ARRAY_MIN_SIZE * sizeof(TUserData));
    if (users == NULL) {
        fprintf(stderr, "Failed to malloc initial array for users\n");
        regfree(&usernameValidationRegex);
        regfree(&passwordValidationRegex);
        return -1;
    }
    usersCapacity = USERS_ARRAY_MIN_SIZE;

    usersFile = (usersFileParam != NULL && usersFileParam[0] != '\0') ? usersFileParam : USERS_DEFAULT_FILE;
    loadUsersFile();

    if (usersLength == 0)
        usersCreate(USERS_DEFAULT_USERNAME, USERS_DEFAULT_PASSWORD, 0, UPRIV_ADMIN, 0);

    return 0;
}

TUserStatus usersLogin(const char* username, const char* password, TUserPriviligeLevel* outLevel) {
    if (password == NULL)
        password = "";

    if (usersLength == 0) {
        fprintf(stderr, "WARNING: Login failed because there are no users in the system\n"); // TODO: Use logging system
        return EUSER_WRONGUSERNAME;
    }

    // Find the index in the users array with the requested username. Return an error if there's no such user.
    int index = usersGetIndexOf(username);
    if (index < 0)
        return EUSER_WRONGUSERNAME;

    int c = strcmp(users[index].password, password);
    if (c != 0)
        return EUSER_WRONGPASSWORD;

    *outLevel = users[index].priviligeLevel;
    return EUSER_OK;
}

TUserStatus usersCreate(const char* username, const char* password, int updatePassword, TUserPriviligeLevel privilige, int updatePrivilige) {
    if (password == NULL)
        password = "";

    // Calculate the index at which the user is, or should be.
    int index = usersGetIndexOf(username);
    if (index >= 0) {
        // The user already exists. Let's see if we need to update anything.
        if (!updatePassword && !updatePrivilige)
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

        if (updatePrivilige && user->priviligeLevel != privilige) {
            if (user->priviligeLevel == UPRIV_ADMIN && adminUsersCount == 1) {
                status = EUSER_BADOPERATION;
            } else {
                adminUsersCount--;
                user->priviligeLevel = privilige;
            }
        }

        return status;
    }

    // The user doesn't exist. Let's create it.
    // First we check that we haven't reached the system's limit.
    if (usersLength >= USERS_MAX_COUNT) {
        fprintf(stderr, "ERROR: Attempted to create new user, but the limit of users on the system has been reached\n"); // TODO: Use logging system
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
    users[insertIndex].priviligeLevel = privilige;

    if (privilige == UPRIV_ADMIN)
        adminUsersCount++;

    return EUSER_OK;
}

TUserStatus usersDelete(const char* username) {
    int index = usersGetIndexOf(username);
    if (index < 0)
        return EUSER_WRONGUSERNAME;

    if (users[index].priviligeLevel == UPRIV_ADMIN) {
        if (adminUsersCount == 1)
            return EUSER_BADOPERATION;
        adminUsersCount--;
    }

    usersLength--;
    memmove(&users[index], &users[index + 1], (usersLength - index) * sizeof(TUserData));

    return EUSER_OK;
}

TUserStatus usersFinalize() {
    free(users);
    regfree(&usernameValidationRegex);
    regfree(&passwordValidationRegex);
    return EUSER_OK;
}

void usersPrintAllDebug() {
    if (usersLength == 0) {
        printf("There are no users in the system.\n");
        return;
    }

    printf("Printing all %d users:\n", usersLength);
    for (int i = 0; i < usersLength; i++)
        printf("[%d] %s (%s) - %s\n", i, users[i].username, users[i].password, users[i].priviligeLevel == UPRIV_ADMIN ? "Admin" : "Filthy Peasant");
}