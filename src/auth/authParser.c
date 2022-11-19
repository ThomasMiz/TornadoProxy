#include "authParser.h"
#include "../logger.h"

typedef TAuthState (*parseCharacter)(TAuthParser* p, uint8_t c);

static TAuthState parseVersion(TAuthParser* p, uint8_t c);
static TAuthState parseUNameByteCount(TAuthParser* p, uint8_t c);
static TAuthState parseUsername(TAuthParser* p, uint8_t c);
static TAuthState parsePasswdByteCount(TAuthParser* p, uint8_t c);
static TAuthState parsePassword(TAuthParser* p, uint8_t c);
static TAuthState parseEnd(TAuthParser* p, uint8_t c);

static parseCharacter stateRead[] = {
    /* AUTH_VERSION         */ (parseCharacter)parseVersion,
    /* AUTH_ULEN            */ (parseCharacter)parseUNameByteCount,
    /* AUTH_UNAME           */ (parseCharacter)parseUsername,
    /* AUTH_PLEN            */ (parseCharacter)parsePasswdByteCount,
    /* AUTH_PASSWD          */ (parseCharacter)parsePassword,
    /* AUTH_END             */ (parseCharacter)parseEnd,
    /* AUTH_INVALID_VERSION */ (parseCharacter)parseEnd};

void initAuthParser(TAuthParser* p) {
    if (p == NULL)
        return;
    p->state = AUTH_VERSION;
    p->readBytes = 0;
    p->verification = AUTH_ACCESS_DENIED;
}
TAuthState authParse(TAuthParser* p, struct buffer* buffer) {
    while (buffer_can_read(buffer) && p->state != AUTH_END) {
        p->state = stateRead[p->state](p, buffer_read(buffer));
    }
    return p->state;
}

bool hasAuthReadEnded(TAuthParser* p) {
    return p->state == AUTH_END || p->state == AUTH_INVALID_VERSION;
}

bool hasAuthReadErrors(TAuthParser* p) {
    return p->state == AUTH_INVALID_VERSION;
}

TAuthRet fillAuthAnswer(TAuthParser* p, struct buffer* buffer) {
    if (!buffer_can_write(buffer))
        return AUTHR_FULLBUFFER;
    buffer_write(buffer, AUTH_VERSION_1);
    if (!buffer_can_write(buffer))
        return AUTHR_FULLBUFFER;
    buffer_write(buffer, p->verification);
    return AUTHR_OK;
}

static TAuthState parseVersion(TAuthParser* p, uint8_t c) {
    if (c != AUTH_VERSION_1) {
        log(INFO, "Client specified invalid version: %d\n", c);
        return AUTH_INVALID_VERSION;
    }
    return AUTH_ULEN;
}

static TAuthState parseUNameByteCount(TAuthParser* p, uint8_t c) {
    log(DEBUG, "Username length: %d", c);
    if (c == 0) {
        return AUTH_PLEN;
    }
    p->totalBytes = c;
    return AUTH_UNAME;
}

static TAuthState parseUsername(TAuthParser* p, uint8_t c) {
    p->uname[p->readBytes++] = c;
    if (p->totalBytes == p->readBytes) {
        p->readBytes = 0;
        return AUTH_PLEN;
    }
    return AUTH_UNAME;
}
static TAuthState parsePasswdByteCount(TAuthParser* p, uint8_t c) {
    log(DEBUG, "Password length: %d", c);
    if (c == 0) {
        return AUTH_END;
    }
    p->totalBytes = c;
    return AUTH_PASSWD;
}
static TAuthState parsePassword(TAuthParser* p, uint8_t c) {
    p->passwd[p->readBytes++] = c;
    if (p->totalBytes == p->readBytes) {
        p->readBytes = 0;
        return AUTH_END;
    }
    return AUTH_PASSWD;
}
static TAuthState parseEnd(TAuthParser* p, uint8_t c) {
    log(LOG_ERROR, "Trying to call auth parser in END/ERROR state with char: %c", c);
    return p->state;
}