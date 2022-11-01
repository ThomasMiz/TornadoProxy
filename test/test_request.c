#include "../src/request.h"
#include <check.h>

#define length(array) (sizeof(array) / sizeof(*(array)))

START_TEST(ipv4_test) {
    reqParser* p = newRequestParser();
    uint8_t data[] = {0x05, 0x01, 0x00, REQ_ATYP_IPV4,
                      0xFF, 0xFE, 0xFD, 0xFC,
                      0x02, 0x01};
    reqState state = requestRead(p, data, length(data));
    fail_unless(state == REQ_SUCCEDED);
    fail_unless(p->address.ipv4[0] == 0xFF);
    fail_unless(p->address.ipv4[1] == 0xFE);
    fail_unless(p->address.ipv4[2] == 0xFD);
    fail_unless(p->address.ipv4[3] == 0xFC);
    freeRequestParser(p);
}
END_TEST

START_TEST(ipv4_command_not_supported) {
    reqParser* p = newRequestParser();
    uint8_t data[] = {0x05, 0x05, 0x00, REQ_ATYP_IPV4,
                      0xFF, 0xFE, 0xFD, 0xFC,
                      0x02, 0x01};
    reqState state = requestRead(p, data, length(data));
    fail_unless(state == REQ_ERROR_COMMAND_NOT_SUPPORTED);
    freeRequestParser(p);
}
END_TEST

START_TEST(ipv6_test) {
    reqParser* p = newRequestParser();
    uint8_t data[] = {0x05, 0x01, 0x00, REQ_ATYP_IPV6,
                      0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xFF, 0xFE,
                      0xFD, 0xFC, 0xFB, 0xFA, 0xFF, 0xFE, 0xFD, 0xFC,
                      0x02, 0x01};
    reqState state = requestRead(p, data, length(data));

    fail_unless(p->address.ipv6[0] == 0xFF);
    fail_unless(p->address.ipv6[1] == 0xFE);
    fail_unless(p->address.ipv6[2] == 0xFD);
    fail_unless(p->address.ipv6[3] == 0xFC);
    fail_unless(p->address.ipv6[4] == 0xFB);
    fail_unless(p->address.ipv6[5] == 0xFA);
    fail_unless(p->address.ipv6[6] == 0xFF);
    fail_unless(p->address.ipv6[7] == 0xFE);
    fail_unless(p->address.ipv6[8] == 0xFD);
    fail_unless(p->address.ipv6[9] == 0xFC);
    fail_unless(p->address.ipv6[10] == 0xFB);
    fail_unless(p->address.ipv6[11] == 0xFA);
    fail_unless(p->address.ipv6[12] == 0xFF);
    fail_unless(p->address.ipv6[13] == 0xFE);
    fail_unless(p->address.ipv6[14] == 0xFD);
    fail_unless(p->address.ipv6[15] == 0xFC);

    fail_unless(state == REQ_SUCCEDED);
    freeRequestParser(p);
}
END_TEST

START_TEST(dommainname_test) {
    reqParser* p = newRequestParser();
    uint8_t data[] = {0x05, 0x01, 0x00, REQ_ATYP_DOMAINNAME,
                      0x0A, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65,
                      0x2E, 0x63, 0x6F, 0x6D, // google.com
                      0x02, 0x01};
    reqState state = requestRead(p, data, length(data));

    fail_unless(p->address.domainname[0] == 'g');
    fail_unless(p->address.domainname[1] == 'o');
    fail_unless(p->address.domainname[2] == 'o');
    fail_unless(p->address.domainname[3] == 'g');
    fail_unless(p->address.domainname[4] == 'l');
    fail_unless(p->address.domainname[5] == 'e');
    fail_unless(p->address.domainname[6] == '.');
    fail_unless(p->address.domainname[7] == 'c');
    fail_unless(p->address.domainname[8] == 'o');
    fail_unless(p->address.domainname[9] == 'm');

    fail_unless(state == REQ_SUCCEDED);
    freeRequestParser(p);
}
END_TEST

START_TEST(atype_not_supported) {
    reqParser* p = newRequestParser();
    uint8_t data[] = {0x05, 0x01, 0x00, 0x07,
                      0x0A, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65,
                      0x2E, 0x63, 0x6F, 0x6D, // google.com
                      0x02, 0x01};
    reqState state = requestRead(p, data, length(data));

    fail_unless(state == REQ_ERROR_ADDRESS_TYPE_NOT_SUPPORTED);
    freeRequestParser(p);
}
END_TEST

START_TEST(port_test) {
    reqParser* p = newRequestParser();
    uint8_t data[] = {0x05, 0x01, 0x00, REQ_ATYP_IPV4,
                      0xFF, 0xFE, 0xFD, 0xFC,
                      0x02, 0x01};
    reqState state = requestRead(p, data, length(data));
    fail_unless(state == REQ_SUCCEDED);
    fail_unless(p->port == 513);
    freeRequestParser(p);
}
END_TEST

int main(void) {
    Suite* s1 = suite_create("Core");
    TCase* tc1_1 = tcase_create("Core");
    SRunner* sr = srunner_create(s1);
    int nf;

    suite_add_tcase(s1, tc1_1);
    tcase_add_test(tc1_1, ipv4_test);
    tcase_add_test(tc1_1, ipv4_command_not_supported);
    tcase_add_test(tc1_1, ipv6_test);
    tcase_add_test(tc1_1, dommainname_test);
    tcase_add_test(tc1_1, atype_not_supported);
    tcase_add_test(tc1_1, port_test);

    srunner_run_all(sr, CK_ENV);
    nf = srunner_ntests_failed(sr);
    srunner_free(sr);

    return nf == 0 ? 0 : 1;
}