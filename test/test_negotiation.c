#include "../src/negotiation/negotiationParser.h"
#include <check.h>

#define length(array) (sizeof(array) / sizeof(*(array)))

START_TEST(complete_request_no_auth) {
    TNegParser p;
    initNegotiationParser(&p);
    uint8_t data[] = {0x05, 0x01, 0x00};
    struct buffer b;
    buffer_init(&b, length(data), data);
    buffer_write_adv(&b, length(data));
    TNegState state = negotiationRead(&p, &b);
    fail_unless(state == NEG_END, "this should succeed");
    fail_unless(p.authMethod == NEG_METHOD_NO_AUTH);
}
END_TEST

START_TEST(complete_request_invalid_version) {
    TNegParser p;
    initNegotiationParser(&p);
    uint8_t data[] = {0x03, 0x01, 0x00};
    struct buffer b;
    buffer_init(&b, length(data), data);
    buffer_write_adv(&b, length(data));
    TNegState state = negotiationRead(&p, &b);
    fail_unless(state == NEG_ERROR);
    fail_unless(p.authMethod == NEG_METHOD_NO_MATCH);
}
END_TEST

START_TEST(complete_request_invalid_versions) {
    TNegParser p;
    initNegotiationParser(&p);
    uint8_t data[] = {0x03, 0x02, 0x08, 0x05};
    struct buffer b;
    buffer_init(&b, length(data), data);
    buffer_write_adv(&b, length(data));
    TNegState state = negotiationRead(&p, &b);
    fail_unless(state == NEG_ERROR);
    fail_unless(p.authMethod == NEG_METHOD_NO_MATCH);
}
END_TEST

START_TEST(complete_request_no_match_x2) {
    TNegParser p;
    initNegotiationParser(&p);
    uint8_t data[] = {0x05, 0x02, 0x08, 0x05};
    struct buffer b;
    buffer_init(&b, length(data), data);
    buffer_write_adv(&b, length(data));
    TNegState state = negotiationRead(&p, &b);
    fail_unless(state == NEG_END);
    fail_unless(p.authMethod == NEG_METHOD_NO_MATCH);
}
END_TEST

START_TEST(complete_request_match_no_auth) {
    TNegParser p;
    initNegotiationParser(&p);
    uint8_t data[] = {0x05, 0x02, 0x08, 0x00};
    struct buffer b;
    buffer_init(&b, length(data), data);
    buffer_write_adv(&b, length(data));
    TNegState state = negotiationRead(&p, &b);
    fail_unless(state == NEG_END);
    fail_unless(p.authMethod == NEG_METHOD_NO_AUTH);
}
END_TEST

int main(void) {
    Suite* s1 = suite_create("Core");
    TCase* tc1_1 = tcase_create("Core");
    SRunner* sr = srunner_create(s1);
    int nf;

    suite_add_tcase(s1, tc1_1);
    tcase_add_test(tc1_1, complete_request_no_auth);
    tcase_add_test(tc1_1, complete_request_invalid_version);
    tcase_add_test(tc1_1, complete_request_invalid_versions);
    tcase_add_test(tc1_1, complete_request_no_match_x2);
    tcase_add_test(tc1_1, complete_request_match_no_auth);

    srunner_run_all(sr, CK_ENV);
    nf = srunner_ntests_failed(sr);
    srunner_free(sr);

    return nf == 0 ? 0 : 1;
}