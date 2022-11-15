#include "passwordDissector.h"

#define TO_LOWER(x) ((x)|0x20)

typedef TPDStatus (*parseCharacter)(TPDissector* p, uint8_t c);

static TPDStatus readP(TPDissector* p, uint8_t c);
static TPDStatus readA(TPDissector* p, uint8_t c);
static TPDStatus readS(TPDissector* p, uint8_t c);
static TPDStatus readS2(TPDissector* p, uint8_t c);
static TPDStatus readPass(TPDissector* p, uint8_t c);
static TPDStatus parseEnd(TPDissector* p, uint8_t c);


static parseCharacter stateRead[] = {
        /* PDS_PASS_P           */readP,
        /* PDS_PASS_A           */readA,
        /* PDS_PASS_S           */readS,
        /* PDS_PASS_S2          */readS2,
        /* PDS_READING_PASS     */readPass,
        /* PDS_END              */parseEnd};

TPDStatus parseUserData(TPDissector * pd, struct buffer * buffer) {
    while (buffer_can_read(buffer) && pd->state != PDS_END) {
        pd->state = stateRead[pd->state](pd, buffer_read(buffer));
    }
    return pd->state;
}

static TPDStatus readP(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 'p' ? PDS_PASS_A : PDS_PASS_P;
}

static TPDStatus readA(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 'a' ? PDS_PASS_S : PDS_PASS_P;
}

static TPDStatus readS(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 's' ? PDS_PASS_S2 : PDS_PASS_P;
}

static TPDStatus readS2(TPDissector* p, uint8_t c){
    return TO_LOWER(c) == 's' ? PDS_READING_PASS : PDS_PASS_P;
}

static TPDStatus readPass(TPDissector* p, uint8_t c){
    if(p->passIdx < PDS_MAX_PASS_LENGTH /*&& TODO: END CONDITION?? */){
        p->password[p->passIdx++] = c;
        return PDS_READING_PASS;
    }
    p->password[p->passIdx] = 0;
    return PDS_END;
}

/* Should not happen */
static TPDStatus parseEnd(TPDissector* p, uint8_t c){
    return p->state;
}