#include "mgmtAuthParser.h"
#include "logger.h"

typedef MTAuthState (*parseCharacter)(MTAuthParser* p, uint8_t c);

static MTAuthState mgmtParseUNameByteCount(MTAuthParser* p, uint8_t c);
static MTAuthState mgmtParseUsername(MTAuthParser* p, uint8_t c);
static MTAuthState mgmtParsePasswdByteCount(MTAuthParser* p, uint8_t c);
static MTAuthState mgmtParsePassword(MTAuthParser* p, uint8_t c);
static MTAuthState mgmtParseEnd(MTAuthParser* p, uint8_t c);

static parseCharacter stateRead[] = {
    /* AUTH_ULEN            */ (parseCharacter)mgmtParseUNameByteCount,
    /* AUTH_UNAME           */ (parseCharacter) mgmtParseUsername,
    /* AUTH_PLEN            */ (parseCharacter)mgmtParsePasswdByteCount,
    /* AUTH_PASSWD          */ (parseCharacter)mgmtParsePassword,
    /* AUTH_END             */ (parseCharacter)mgmtParseEnd,
    /* AUTH_INVALID_VERSION */ (parseCharacter)mgmtParseEnd};

void mgmtInitAuthParser(MTAuthParser* p) {
    if (p == NULL)
        return;
    p->state = M_AUTH_ULEN;
    p->readBytes = 0;
    p->verification = M_AUTH_ACCESS_DENIED;
}
MTAuthState mgmtAuthParse(MTAuthParser* p, struct buffer* buffer) {
    while (buffer_can_read(buffer) && p->state != M_AUTH_END) {
        p->state = stateRead[p->state](p, buffer_read(buffer));
    }
    return p->state;
}

bool mgmtHasAuthReadEnded(MTAuthParser* p) {
    return p->state == M_AUTH_END || p->state == M_AUTH_INVALID_VERSION;
}

bool mgmtHasAuthReadErrors(MTAuthParser* p) {
    return p->state == M_AUTH_INVALID_VERSION;
}

MTAuthRet mgmtFillAuthAnswer(MTAuthParser* p, struct buffer* buffer) {
    if (!buffer_can_write(buffer))
        return M_AUTHR_FULLBUFFER;
    // buffer_write(buffer, AUTH_VERSION_1);
    if (!buffer_can_write(buffer))
        return M_AUTHR_FULLBUFFER;
    buffer_write(buffer, p->verification);
    return M_AUTHR_OK;
}

static MTAuthState mgmtParseUNameByteCount(MTAuthParser* p, uint8_t c) {
    log(DEBUG, "Username length: %d", c);
    if (c == 0) {
        return M_AUTH_PLEN;
    }
    p->totalBytes = c;
    return M_AUTH_UNAME;
}

static MTAuthState mgmtParseUsername(MTAuthParser* p, uint8_t c) {
    p->uname[p->readBytes++] = c;
    if (p->totalBytes == p->readBytes) {
        p->readBytes = 0;
        return M_AUTH_PLEN;
    }
    return M_AUTH_UNAME;
}
static MTAuthState mgmtParsePasswdByteCount(MTAuthParser* p, uint8_t c) {
    log(DEBUG, "Password length: %d", c);
    if (c == 0) {
        return M_AUTH_END;
    }
    p->totalBytes = c;
    return M_AUTH_PASSWD;
}
static MTAuthState mgmtParsePassword(MTAuthParser* p, uint8_t c) {
    p->passwd[p->readBytes++] = c;
    if (p->totalBytes == p->readBytes) {
        p->readBytes = 0;
        return M_AUTH_END;
    }
    return M_AUTH_PASSWD;
}
static MTAuthState mgmtParseEnd(MTAuthParser* p, uint8_t c) {
    log(LOG_ERROR, "Trying to call auth parser in END/ERROR state with char: %c", c);
    return p->state;
}