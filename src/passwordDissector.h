#ifndef PASSWORD_DISSECTOR_H_
#define PASSWORD_DISSECTOR_H_

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define PDS_MAX_PASS_LENGTH 255

typedef enum TPDStatus{
    PDS_PASS_P,         //  waiting for P of PASS
    PDS_PASS_A,         //  waiting for A of PASS
    PDS_PASS_S,         //  waiting for first S of PASS
    PDS_PASS_S2,        //  waiting for second S of PASS
    PDS_READING_PASS,   //  reading the password
    PDS_END             //  Password read completely
}TPDStatus;

typedef struct TPDissector{
    TPDStatus state;
    uint8_t passIdx;         // used to store de password
    char password[PDS_MAX_PASS_LENGTH +1];
    bool isOn;   // PD will only be active if the config indicates it to be active and if the client is tring to connect
}TPDissector;

void initPDissector(TPDissector * pd);
TPDStatus parseUserData(TPDissector * pd, struct buffer * buffer);

#endif // PASSWORD_DISSECTOR_H_