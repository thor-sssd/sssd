/*
   SSSD

   Tests for local computer object

   Authors:
      Thomas Reim <reimth@gmail.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/common.h"
#include "db/sysdb_computer.h"
#include "db/sysdb_private.h" /* for sysdb->ldb member */

/* In order to access function ad_gpo_cache_refresh_status() */
#include "providers/ad/ad_gpo.c"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_sysdb_computer.ldb"
#define TEST_ID_PROVIDER "ad"
#define TEST_DOM_NAME "testdomain.test"

struct computer_test_ctx {
    struct sss_test_ctx *tctx;
    struct test_data *data;
};

struct test_data {
    struct computer_test_ctx *tctx;

    const char *hostname;
    const char *host_dn;
    const char *host_sid;
    const char **host_group_sids;
    int num_host_groups;

    struct gp_gpo **linked_gpos;
    const char **gpo_cse_dn_list;
    int num_linked_gpos;
    int gpo_container_version_new;
    int gpo_container_version_ignore;
    int gpo_file_system_version_new;
    int gpo_file_system_version_ignore;
    int gpo_cse_version;

    struct ldb_result *res;

    struct ldb_message *msg;

    size_t msgs_count;
    struct ldb_message **msgs;
};

static struct test_data *test_data_new(struct computer_test_ctx *test_ctx)
{
    struct test_data *data;

    data = talloc_zero(test_ctx, struct test_data);
    if (data == NULL) {
        return NULL;
    }

    data->tctx = test_ctx;

    return data;
}

static struct test_data *test_data_new_computer(struct computer_test_ctx *test_ctx)
{
    static const char *group_sids[] =
            {"S-1-5-21-1961322486-2366424238-2351687912-515",
             "S-1-5-11"};
    static const char *test_cse_guid[] =
            {"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", NULL};
    static const char *test_guid[] = {"{2F1FD423-D089-4DF5-AFAA-8C2B0E340464}",
                                      "{AB19E078-6405-40AA-BA43-635E95D090AF}",
                                      "{32EF709E-1337-4947-8794-5E53E958F1AE}"};
    static const char *test_gpo_dn[] = {
        "cn={2F1FD423-D089-4DF5-AFAA-8C2B0E340464},cn=policies,cn=system,DC=testdomain,DC=test",
        "cn={AB19E078-6405-40AA-BA43-635E95D090AF},cn=policies,cn=system,DC=testdomain,DC=test",
        "cn={32EF709E-1337-4947-8794-5E53E958F1AE},cn=policies,cn=system,DC=testdomain,DC=test"};
    static const char *test_gpo_name[] = {"SYSDB Computer Test GPO #1",
                                          "SYSDB Computer Test GPO #2",
                                          "SYSDB Computer Test GPO #3"};
    static const char *test_cse_dn[] = {
        "cseGUID={827D319E-6EAC-11D2-A4EA-00C04F79F83A},"
            "gpoGUID={2F1FD423-D089-4DF5-AFAA-8C2B0E340464},"
            "cn=gpos,cn=ad,cn=custom,cn=testdomain.test,cn=sysdb",
        "cseGUID={827D319E-6EAC-11D2-A4EA-00C04F79F83A},"
            "gpoGUID={AB19E078-6405-40AA-BA43-635E95D090AF},"
            "cn=gpos,cn=ad,cn=custom,cn=testdomain.test,cn=sysdb",
        "cseGUID={827D319E-6EAC-11D2-A4EA-00C04F79F83A},"
            "gpoGUID={32EF709E-1337-4947-8794-5E53E958F1AE},"
            "cn=gpos,cn=ad,cn=custom,cn=testdomain.test,cn=sysdb"};
    struct test_data *data;
    int i, k;

    data = test_data_new(test_ctx);
    if (data == NULL) {
        return NULL;
    }

    data->hostname = "TESTSERVER$";
    data->host_dn = "CN=TESTSERVER,CN=Computers,DC=testdomain,DC=test";
    data->host_sid = "S-1-5-21-1961322486-2366424238-2351687912-1168";
    data->num_host_groups = 2;
    data->host_group_sids = talloc_array(data,
                                         const char *,
                                         data->num_host_groups + 1);
    if (data->host_group_sids == NULL) {
        return NULL;
    }
    for (i = 0; i < data->num_host_groups; i++) {
        data->host_group_sids[i] = group_sids[i];
    }
    data->host_group_sids[data->num_host_groups] = NULL;

    data->num_linked_gpos = 3;
    data->linked_gpos = talloc_array(data,
                                     struct gp_gpo *,
                                     data->num_linked_gpos + 1);
    if (data->linked_gpos == NULL) {
        return NULL;
    }
    for (i = 0; i < data->num_linked_gpos; i++) {
        data->linked_gpos[i] = talloc_zero(data->linked_gpos, struct gp_gpo);
        data->linked_gpos[i]->gpo_cse_guids = talloc_array(data->linked_gpos[i],
                                                           const char *,
                                                           2);
        data->linked_gpos[i]->num_gpo_cse_guids = 2;
        for (k = 0; k < data->linked_gpos[i]->num_gpo_cse_guids; k++) {
            data->linked_gpos[i]->gpo_cse_guids[k] = test_cse_guid[k];
        }
        data->linked_gpos[i]->gpo_dn = test_gpo_dn[i];
        data->linked_gpos[i]->gpo_display_name = test_gpo_name[i];
        data->linked_gpos[i]->gpo_guid = test_guid[i];
        data->linked_gpos[i]->gpo_container_version = 0x1000400;
        data->linked_gpos[i]->gpo_file_system_version = 0xFF03FF;
    }
    data->gpo_cse_dn_list = talloc_array(data,
                                         const char *,
                                         data->num_linked_gpos + 1);
    if (data->gpo_cse_dn_list == NULL) {
        return NULL;
    }
    for (i = 0; i < data->num_linked_gpos; i++) {
        data->gpo_cse_dn_list[i] = test_cse_dn[i];
    }
    data->gpo_cse_dn_list[data->num_linked_gpos] = NULL;
    data->gpo_container_version_new = 0x1000401;
    data->gpo_container_version_ignore = 0x2000400;
    data->gpo_file_system_version_new = 0xFF00400;
    data->gpo_file_system_version_ignore = 0xFFF03FF;
    data->gpo_cse_version = 0x3FF0400;

    return data;
}

static bool is_in_list(const char **str_list,
                       int element_count,
                       const char *str)
{
    bool res = false;
    size_t len1, len2;
    int i;

    if (str == NULL) {
        return res;
    }
    len1 = strlen(str);

    for (i=0; i<element_count; i++) {
        len2 = strlen(str_list[i]);
        if (len1 == len2) {
            res = (strncasecmp(str, str_list[i], len1) == 0);
        }
        if (res) break;
    }

    return res;
}

static int test_sysdb_computer_setup(void **state)
{
    struct computer_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct computer_test_ctx);
    assert_non_null(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH,
                                         TEST_CONF_DB, TEST_DOM_NAME,
                                         TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    test_ctx->data = test_data_new_computer(test_ctx);
    assert_non_null(test_ctx->data);

    reset_ldb_errstrings(test_ctx->tctx->dom);
    check_leaks_push(test_ctx);

    *state = (void *)test_ctx;
    return 0;
}

static int test_sysdb_computer_teardown(void **state)
{
    struct computer_test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct computer_test_ctx);

    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);

    reset_ldb_errstrings(test_ctx->tctx->dom);
    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);
    assert_true(leak_check_teardown());

    return 0;
}

void test_modify_computer_group(void **state)
{
    const char *attrs[] = {SYSDB_NAME, SYSDB_SID_STR, SYSDB_MEMBEROF_SID_STR,
                           SYSDB_ORIG_DN, SYSDB_GPLINK_STR,
                           SYSDB_CACHE_EXPIRE, SYSDB_CREATE_TIME,
                           NULL};
    const char *mod_group_sids[] = {"S-1-5-11",
                                    "S-1-5-21-1961322486-2366424238-2351687912-516",
                                    "S-1-5-21-1961322486-2366424238-2351687912-553"};
    struct ldb_message_element *el;
    time_t value_time, now;
    int lret;
    int i;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 6);

    talloc_free(test_ctx->data->msg);

    lret = sysdb_set_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              test_ctx->data->host_dn,
                              test_ctx->data->host_sid,
                              mod_group_sids,
                              3,
                              5, 0);
    assert_int_equal(lret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 6);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_MEMBEROF_SID_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 3);
    for (i=0; i<el->num_values; i++) {
        assert_true(is_in_list(mod_group_sids, 3, (char *)el->values[i].data));
    }

    value_time = ldb_msg_find_attr_as_uint64(test_ctx->data->msg,
                                             SYSDB_CACHE_EXPIRE, 0);
    assert_int_equal(value_time, 5);

    talloc_free(test_ctx->data->msg);

    now = time(NULL);
    lret = sysdb_set_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              test_ctx->data->host_dn,
                              test_ctx->data->host_sid,
                              test_ctx->data->host_group_sids,
                              test_ctx->data->num_host_groups,
                              5, now);
    assert_int_equal(lret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 6);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_MEMBEROF_SID_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 2);
    for (i=0; i<el->num_values; i++) {
        assert_true(is_in_list(test_ctx->data->host_group_sids,
                               test_ctx->data->num_host_groups,
                               (char *)el->values[i].data));
    }

    value_time = ldb_msg_find_attr_as_uint64(test_ctx->data->msg,
                                             SYSDB_CACHE_EXPIRE, 0);
    assert_int_equal(value_time, now + 5);

    talloc_free(test_ctx->data->msg);
    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_modify_computer_sid(void **state)
{
    const char *attrs[] = {SYSDB_NAME, SYSDB_SID_STR, SYSDB_MEMBEROF_SID_STR,
                           SYSDB_ORIG_DN, SYSDB_GPLINK_STR,
                           SYSDB_CACHE_EXPIRE, SYSDB_CREATE_TIME,
                           NULL};
    const char *new_host_sid = "S-1-5-21-1961322486-2366424238-2351687912-30000";
    const char *value_str;
    time_t value_time, now;
    int lret;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 6);

    talloc_free(test_ctx->data->msg);

    now = time(NULL);
    lret = sysdb_set_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              test_ctx->data->host_dn,
                              new_host_sid,
                              test_ctx->data->host_group_sids,
                              test_ctx->data->num_host_groups,
                              5, now - 6);
    assert_int_equal(lret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 6);

    value_str = ldb_msg_find_attr_as_string(test_ctx->data->msg,
                                            SYSDB_SID_STR, NULL);
    assert_string_equal(value_str, new_host_sid);

    value_time = ldb_msg_find_attr_as_uint64(test_ctx->data->msg,
                                             SYSDB_CACHE_EXPIRE, 0);
    assert_int_equal(value_time, now -1);

    talloc_free(test_ctx->data->msg);

    lret = sysdb_set_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              test_ctx->data->host_dn,
                              test_ctx->data->host_sid,
                              test_ctx->data->host_group_sids,
                              test_ctx->data->num_host_groups,
                              0, 0);
    assert_int_equal(lret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 6);

    value_str = ldb_msg_find_attr_as_string(test_ctx->data->msg,
                                            SYSDB_SID_STR, NULL);
    assert_string_equal(value_str, test_ctx->data->host_sid);

    value_time = ldb_msg_find_attr_as_uint64(test_ctx->data->msg,
                                             SYSDB_CACHE_EXPIRE, 0);
    assert_int_equal(value_time, 0);

    talloc_free(test_ctx->data->msg);
    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_store_gp_links(void **state)
{
    const char *attrs[] = {SYSDB_NAME, SYSDB_SID_STR, SYSDB_MEMBEROF_SID_STR,
                           SYSDB_ORIG_DN, SYSDB_GPLINK_STR,
                           SYSDB_CACHE_EXPIRE, SYSDB_CREATE_TIME,
                           NULL};
    struct ldb_message_element *el;
    errno_t ret;
    int lret;
    int i;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 6);

    talloc_free(test_ctx->data->msg);

    ret = sysdb_computer_setgplinks(test_ctx->tctx->dom,
                                    test_ctx->data->hostname,
                                    test_ctx->data->gpo_cse_dn_list,
                                    test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 7);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 3);
    for (i=0; i<el->num_values; i++) {
        assert_true(is_in_list(test_ctx->data->gpo_cse_dn_list,
                               test_ctx->data->num_linked_gpos,
                               (char *)el->values[i].data));
    }

    talloc_free(test_ctx->data->msg);
    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_modify_gp_links(void **state)
{
    static const char *test_cse_dn[] = {
        "cseGUID={827D319E-6EAC-11D2-A4EA-00C04F79F83A},"
            "gpoGUID={31B2F340-016D-11D2-945F-00C04FB984F9},"
            "cn=gpos,cn=ad,cn=custom,cn=testdomain.test,cn=sysdb",
        NULL};
    const char *attrs[] = {SYSDB_GPLINK_STR, NULL};
    const char *value_str;
    errno_t ret;
    int lret;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    talloc_free(test_ctx->data->msg);

    ret = sysdb_computer_setgplinks(test_ctx->tctx->dom,
                                    test_ctx->data->hostname,
                                    test_cse_dn,
                                    1);
    assert_int_equal(ret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    value_str = ldb_msg_find_attr_as_string(test_ctx->data->msg,
                                            SYSDB_GPLINK_STR, NULL);
    assert_true(is_in_list(test_cse_dn, 1, value_str));

    talloc_free(test_ctx->data->msg);
    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_remove_gp_links(void **state)
{
    static const char *test_cse_dn[] = {NULL};
    const char *attrs[] = {SYSDB_GPLINK_STR, NULL};
    errno_t ret;
    int lret;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    talloc_free(test_ctx->data->msg);

    ret = sysdb_computer_setgplinks(test_ctx->tctx->dom,
                                    test_ctx->data->hostname,
                                    test_cse_dn,
                                    0);
    assert_int_equal(ret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 0);

    talloc_free(test_ctx->data->msg);
    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_check_gpo_cache_status_no_gpo(void **state)
{
    const char *attrs[] = {SYSDB_GPLINK_STR, NULL};
    const char *gpo_cse_attrs[] = {SYSDB_CSE_VERSION_ATTR,
                                   SYSDB_CSE_TIMEOUT_ATTR,
                                   NULL};
    static const char *test_cse_dn[] = {NULL};
    const char *gpo_cse_guid;
    errno_t ret;
    int lret;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);
    gpo_cse_guid = test_ctx->data->linked_gpos[0]->gpo_cse_guids[0],

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 0);

    talloc_free(test_ctx->data->msg);

    ret = sysdb_gpo_cse_search(test_ctx,
                               test_ctx->tctx->dom,
                               gpo_cse_guid,
                               gpo_cse_attrs,
                               &test_ctx->data->msgs_count,
                               &test_ctx->data->msgs);
    assert_int_equal(ret, ENOENT);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_cse_dn,
                                      0);
    assert_int_equal(ret, EOK);

    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_check_gpo_cache_status_no_refresh(void **state)
{
    const char *attrs[] = {SYSDB_NAME, SYSDB_SID_STR, SYSDB_MEMBEROF_SID_STR,
                           SYSDB_ORIG_DN, SYSDB_GPLINK_STR,
                           SYSDB_CACHE_EXPIRE, SYSDB_CREATE_TIME,
                           NULL};
    const char *gpo_cse_attrs[] = {SYSDB_CSE_VERSION_ATTR,
                                   SYSDB_CSE_TIMEOUT_ATTR,
                                   NULL};
    const char *gpo_attrs[] = {SYSDB_GPO_AD_VERSION_ATTR,
                               SYSDB_GPO_SYSVOL_VERSION_ATTR,
                               SYSDB_GPO_TIMEOUT_ATTR,
                               NULL};
    struct ldb_message_element *el;
    struct test_data *data;
    const char *gpo_cse_guid;
    int version;
    time_t now, timeout;
    errno_t ret;
    int lret;
    int i;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);
    data = test_ctx->data;
    gpo_cse_guid = data->linked_gpos[0]->gpo_cse_guids[0],

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 6);

    talloc_free(test_ctx->data->msg);

    now = time(NULL);
    for(i = 0; i < data->num_linked_gpos; i++) {
        ret = sysdb_gpo_store_gpo(test_ctx->tctx->dom,
                                  data->linked_gpos[i]->gpo_guid,
                                  data->linked_gpos[i]->gpo_dn,
                                  data->linked_gpos[i]->gpo_display_name,
                                  data->linked_gpos[i]->gpo_container_version,
                                  data->linked_gpos[i]->gpo_file_system_version,
                                  5, now);
        assert_int_equal(ret, EOK);

        ret = sysdb_gpo_store_cse(test_ctx->tctx->dom,
                                  data->linked_gpos[i]->gpo_guid,
                                  gpo_cse_guid,
                                  data->gpo_cse_version,
                                  5, now);
        assert_int_equal(ret, EOK);
    }

    ret = sysdb_gpo_cse_search(test_ctx,
                               test_ctx->tctx->dom,
                               gpo_cse_guid,
                               gpo_cse_attrs,
                               &data->msgs_count,
                               &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);
    for (i = 0; i < 3; i++) {
        assert_non_null(test_ctx->data->msgs);
        version = ldb_msg_find_attr_as_uint(data->msgs[i],
                                            SYSDB_CSE_VERSION_ATTR, 0);
        assert_int_equal(version, data->gpo_cse_version);

        timeout = ldb_msg_find_attr_as_uint64(data->msgs[i],
                                              SYSDB_CSE_TIMEOUT_ATTR, 0);
        assert_int_equal(timeout, now + 5);
    }

    talloc_free(test_ctx->data->msgs);

    ret = sysdb_gpo_cse_search_parent_gpo(test_ctx,
                                          test_ctx->tctx->dom,
                                          gpo_cse_guid,
                                          gpo_attrs,
                                          &data->msgs_count,
                                          &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);
    for (i = 0; i < 3; i++) {
        assert_non_null(test_ctx->data->msgs);
        version = ldb_msg_find_attr_as_uint(data->msgs[i],
                                            SYSDB_GPO_AD_VERSION_ATTR, 0);
        assert_int_equal(version, data->linked_gpos[i]->gpo_container_version);

        version = ldb_msg_find_attr_as_uint(data->msgs[i],
                                            SYSDB_GPO_SYSVOL_VERSION_ATTR, 0);
        assert_int_equal(version, data->linked_gpos[i]->gpo_file_system_version);

        timeout = ldb_msg_find_attr_as_uint64(data->msgs[i],
                                              SYSDB_GPO_TIMEOUT_ATTR, 0);
        assert_int_equal(timeout, now + 5);
    }

    ret = sysdb_computer_setgplinks(test_ctx->tctx->dom,
                                    test_ctx->data->hostname,
                                    test_ctx->data->gpo_cse_dn_list,
                                    test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    talloc_free(test_ctx->data->msgs);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 7);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 3);
    for (i=0; i<el->num_values; i++) {
        assert_true(is_in_list(test_ctx->data->gpo_cse_dn_list,
                               test_ctx->data->num_linked_gpos,
                               (char *)el->values[i].data));
    }

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    talloc_free(test_ctx->data->msg);
    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_check_gpo_cache_status_fs_version_change(void **state)
{
    const char *attrs[] = {SYSDB_GPLINK_STR,
                           NULL};
    const char *gpo_cse_attrs[] = {SYSDB_CSE_VERSION_ATTR,
                                   SYSDB_CSE_TIMEOUT_ATTR,
                                   NULL};
    const char *gpo_attrs[] = {SYSDB_GPO_AD_VERSION_ATTR,
                               SYSDB_GPO_SYSVOL_VERSION_ATTR,
                               SYSDB_GPO_TIMEOUT_ATTR,
                               NULL};
    struct ldb_message_element *el;
    struct test_data *data;
    const char *gpo_cse_guid;
    time_t now;
    int version;
    errno_t ret;
    int lret;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);
    data = test_ctx->data;
    gpo_cse_guid = data->linked_gpos[0]->gpo_cse_guids[0],

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 3);

    talloc_free(test_ctx->data->msg);

    ret = sysdb_gpo_cse_search(test_ctx,
                               test_ctx->tctx->dom,
                               gpo_cse_guid,
                               gpo_cse_attrs,
                               &data->msgs_count,
                               &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);

    talloc_free(test_ctx->data->msgs);

    ret = sysdb_gpo_cse_search_parent_gpo(test_ctx,
                                          test_ctx->tctx->dom,
                                          gpo_cse_guid,
                                          gpo_attrs,
                                          &data->msgs_count,
                                          &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);

    talloc_free(test_ctx->data->msgs);

    now = time(NULL);
    ret = sysdb_gpo_store_gpo(test_ctx->tctx->dom,
                              data->linked_gpos[2]->gpo_guid,
                              data->linked_gpos[2]->gpo_dn,
                              data->linked_gpos[2]->gpo_display_name,
                              data->linked_gpos[2]->gpo_container_version,
                              data->gpo_file_system_version_new,
                              5, now);
    assert_int_equal(ret, EOK);

    ret = sysdb_gpo_get_gpo_by_guid(test_ctx,
                                    test_ctx->tctx->dom,
                                    data->linked_gpos[2]->gpo_guid,
                                    gpo_attrs,
                                    &data->res);
    assert_int_equal(ret, EOK);
    assert_non_null(data->res);
    assert_non_null(data->res->msgs[0]);
    version = ldb_msg_find_attr_as_uint(data->res->msgs[0],
                                        SYSDB_GPO_SYSVOL_VERSION_ATTR, 0);
    assert_int_equal(version, data->gpo_file_system_version_new);

    talloc_free(test_ctx->data->res);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EINVAL);

    ret = sysdb_gpo_store_gpo(test_ctx->tctx->dom,
                              data->linked_gpos[2]->gpo_guid,
                              data->linked_gpos[2]->gpo_dn,
                              data->linked_gpos[2]->gpo_display_name,
                              data->linked_gpos[2]->gpo_container_version,
                              data->linked_gpos[2]->gpo_file_system_version,
                              5, now);
    assert_int_equal(ret, EOK);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_check_gpo_cache_status_ad_version_change(void **state)
{
    const char *attrs[] = {SYSDB_GPLINK_STR,
                           NULL};
    const char *gpo_cse_attrs[] = {SYSDB_CSE_VERSION_ATTR,
                                   SYSDB_CSE_TIMEOUT_ATTR,
                                   NULL};
    const char *gpo_attrs[] = {SYSDB_GPO_AD_VERSION_ATTR,
                               SYSDB_GPO_SYSVOL_VERSION_ATTR,
                               SYSDB_GPO_TIMEOUT_ATTR,
                               NULL};
    struct ldb_message_element *el;
    struct test_data *data;
    const char *gpo_cse_guid;
    time_t now;
    int version;
    errno_t ret;
    int lret;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);
    data = test_ctx->data;
    gpo_cse_guid = data->linked_gpos[0]->gpo_cse_guids[0],

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 3);

    talloc_free(test_ctx->data->msg);

    ret = sysdb_gpo_cse_search(test_ctx,
                               test_ctx->tctx->dom,
                               gpo_cse_guid,
                               gpo_cse_attrs,
                               &data->msgs_count,
                               &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);

    talloc_free(test_ctx->data->msgs);

    ret = sysdb_gpo_cse_search_parent_gpo(test_ctx,
                                          test_ctx->tctx->dom,
                                          gpo_cse_guid,
                                          gpo_attrs,
                                          &data->msgs_count,
                                          &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);

    talloc_free(test_ctx->data->msgs);

    now = time(NULL);
    ret = sysdb_gpo_store_gpo(test_ctx->tctx->dom,
                              data->linked_gpos[0]->gpo_guid,
                              data->linked_gpos[0]->gpo_dn,
                              data->linked_gpos[0]->gpo_display_name,
                              data->gpo_container_version_new,
                              data->linked_gpos[0]->gpo_file_system_version,
                              5, now);
    assert_int_equal(ret, EOK);

    ret = sysdb_gpo_get_gpo_by_guid(test_ctx,
                                    test_ctx->tctx->dom,
                                    data->linked_gpos[0]->gpo_guid,
                                    gpo_attrs,
                                    &data->res);
    assert_int_equal(ret, EOK);
    assert_non_null(data->res);
    assert_non_null(data->res->msgs[0]);
    version = ldb_msg_find_attr_as_uint(data->res->msgs[0],
                                        SYSDB_GPO_AD_VERSION_ATTR, 0);
    assert_int_equal(version, data->gpo_container_version_new);

    talloc_free(test_ctx->data->res);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EINVAL);

    ret = sysdb_gpo_store_gpo(test_ctx->tctx->dom,
                              data->linked_gpos[0]->gpo_guid,
                              data->linked_gpos[0]->gpo_dn,
                              data->linked_gpos[0]->gpo_display_name,
                              data->linked_gpos[0]->gpo_container_version,
                              data->linked_gpos[0]->gpo_file_system_version,
                              5, now);
    assert_int_equal(ret, EOK);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_check_gpo_cache_status_user_version_change(void **state)
{
    const char *attrs[] = {SYSDB_GPLINK_STR,
                           NULL};
    const char *gpo_cse_attrs[] = {SYSDB_CSE_VERSION_ATTR,
                                   SYSDB_CSE_TIMEOUT_ATTR,
                                   NULL};
    const char *gpo_attrs[] = {SYSDB_GPO_AD_VERSION_ATTR,
                               SYSDB_GPO_SYSVOL_VERSION_ATTR,
                               SYSDB_GPO_TIMEOUT_ATTR,
                               NULL};
    struct ldb_message_element *el;
    struct test_data *data;
    const char *gpo_cse_guid;
    time_t now;
    int version;
    errno_t ret;
    int lret;
    int i;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);
    data = test_ctx->data;
    gpo_cse_guid = data->linked_gpos[0]->gpo_cse_guids[0],

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 3);

    talloc_free(test_ctx->data->msg);

    ret = sysdb_gpo_cse_search(test_ctx,
                               test_ctx->tctx->dom,
                               gpo_cse_guid,
                               gpo_cse_attrs,
                               &data->msgs_count,
                               &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);

    talloc_free(test_ctx->data->msgs);

    ret = sysdb_gpo_cse_search_parent_gpo(test_ctx,
                                          test_ctx->tctx->dom,
                                          gpo_cse_guid,
                                          gpo_attrs,
                                          &data->msgs_count,
                                          &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);

    talloc_free(test_ctx->data->msgs);

    now = time(NULL);
    for (i = 0; i < data->num_linked_gpos; i++) {
        ret = sysdb_gpo_store_gpo(test_ctx->tctx->dom,
                                  data->linked_gpos[i]->gpo_guid,
                                  data->linked_gpos[i]->gpo_dn,
                                  data->linked_gpos[i]->gpo_display_name,
                                  data->gpo_container_version_ignore,
                                  data->gpo_file_system_version_ignore,
                                  5, now);
        assert_int_equal(ret, EOK);
    }

    for (i = 0; i < data->num_linked_gpos; i++) {
        ret = sysdb_gpo_get_gpo_by_guid(test_ctx,
                                        test_ctx->tctx->dom,
                                        data->linked_gpos[i]->gpo_guid,
                                        gpo_attrs,
                                        &data->res);
        assert_int_equal(ret, EOK);
        assert_non_null(data->res);
        assert_non_null(data->res->msgs[0]);
        version = ldb_msg_find_attr_as_uint(data->res->msgs[0],
                                            SYSDB_GPO_AD_VERSION_ATTR, 0);
        assert_int_equal(version, data->gpo_container_version_ignore);
        version = ldb_msg_find_attr_as_uint(data->res->msgs[0],
                                            SYSDB_GPO_SYSVOL_VERSION_ATTR, 0);
        assert_int_equal(version, data->gpo_file_system_version_ignore);

        talloc_free(test_ctx->data->res);
    }

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    for (i = 0; i < data->num_linked_gpos; i++) {
        ret = sysdb_gpo_store_gpo(test_ctx->tctx->dom,
                                  data->linked_gpos[i]->gpo_guid,
                                  data->linked_gpos[i]->gpo_dn,
                                  data->linked_gpos[i]->gpo_display_name,
                                  data->linked_gpos[i]->gpo_container_version,
                                  data->linked_gpos[i]->gpo_file_system_version,
                                  5, now);
        assert_int_equal(ret, EOK);
    }

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_check_gpo_cache_status_timeout(void **state)
{
    const char *attrs[] = {SYSDB_GPLINK_STR,
                           NULL};
    const char *gpo_cse_attrs[] = {SYSDB_CSE_VERSION_ATTR,
                                   SYSDB_CSE_TIMEOUT_ATTR,
                                   NULL};
    struct test_data *data;
    const char *gpo_cse_guid;
    time_t now, timeout;
    errno_t ret;
    int lret;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);
    data = test_ctx->data;
    gpo_cse_guid = data->linked_gpos[0]->gpo_cse_guids[0],

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    talloc_free(test_ctx->data->msg);

    now = time(NULL);
    ret = sysdb_gpo_store_cse(test_ctx->tctx->dom,
                              data->linked_gpos[1]->gpo_guid,
                              gpo_cse_guid,
                              data->gpo_cse_version,
                              5, now - 6);
    assert_int_equal(ret, EOK);

    ret = sysdb_gpo_get_cse_by_guid(test_ctx,
                                    test_ctx->tctx->dom,
                                    data->linked_gpos[1]->gpo_guid,
                                    gpo_cse_guid,
                                    gpo_cse_attrs,
                                    &data->res);
    assert_int_equal(ret, EOK);
    assert_non_null(data->res);
    assert_non_null(data->res->msgs[0]);
    timeout = ldb_msg_find_attr_as_uint64(data->res->msgs[0],
                                          SYSDB_CSE_TIMEOUT_ATTR, 0);
    assert_int_equal(timeout, now - 1);

    talloc_free(test_ctx->data->res);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EINVAL);

    ret = sysdb_gpo_store_cse(test_ctx->tctx->dom,
                              data->linked_gpos[1]->gpo_guid,
                              gpo_cse_guid,
                              data->gpo_cse_version,
                              5, now);
    assert_int_equal(ret, EOK);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_check_gpo_cache_status_gp_links(void **state)
{
    static const char *test_cse_dn[] = {
        "cseGUID={827D319E-6EAC-11D2-A4EA-00C04F79F83A},"
            "gpoGUID={2F1FD423-D089-4DF5-AFAA-8C2B0E340464},"
            "cn=gpos,cn=ad,cn=custom,cn=testdomain.test,cn=sysdb",
        "cseGUID={827D319E-6EAC-11D2-A4EA-00C04F79F83A},"
            "gpoGUID={AB19E078-6405-40AA-BA43-635E95D090AF},"
            "cn=gpos,cn=ad,cn=custom,cn=testdomain.test,cn=sysdb",
        "cseGUID={827D319E-6EAC-11D2-A4EA-00C04F79F83A},"
            "gpoGUID={32EF709E-1337-4947-8794-5E53E958F1AE},"
            "cn=gpos,cn=ad,cn=custom,cn=testdomain.test,cn=sysdb",
        "cseGUID={827D319E-6EAC-11D2-A4EA-00C04F79F83A},"
            "gpoGUID={31B2F340-016D-11D2-945F-00C04FB984F9},"
            "cn=gpos,cn=ad,cn=custom,cn=testdomain.test,cn=sysdb"};
    const char *attrs[] = {SYSDB_GPLINK_STR,
                           NULL};
    const char *gpo_cse_guid;
    struct ldb_message_element *el;
    errno_t ret;
    int lret;
    int i;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);
    gpo_cse_guid = test_ctx->data->linked_gpos[0]->gpo_cse_guids[0],

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 3);
    for (i=0; i<el->num_values; i++) {
        assert_true(is_in_list(test_ctx->data->gpo_cse_dn_list,
                               test_ctx->data->num_linked_gpos,
                               (char *)el->values[i].data));
    }

    talloc_free(test_ctx->data->msg);

    ret = sysdb_computer_setgplinks(test_ctx->tctx->dom,
                                    test_ctx->data->hostname,
                                    test_cse_dn,
                                    4);
    assert_int_equal(ret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 4);
    for (i=0; i<el->num_values; i++) {
        assert_true(is_in_list(test_cse_dn,
                               4,
                               (char *)el->values[i].data));
    }

    talloc_free(test_ctx->data->msg);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_cse_dn,
                                      4);
    assert_int_equal(ret, ENOENT);

    ret = sysdb_computer_setgplinks(test_ctx->tctx->dom,
                                    test_ctx->data->hostname,
                                    test_ctx->data->gpo_cse_dn_list,
                                    test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_check_gpo_cache_status_cse_gpo(void **state)
{
    const char *attrs[] = {SYSDB_GPLINK_STR,
                           NULL};
    const char *gpo_cse_attrs[] = {SYSDB_CSE_VERSION_ATTR,
                                   SYSDB_CSE_TIMEOUT_ATTR,
                                   NULL};
    const char *gpo_attrs[] = {SYSDB_GPO_AD_VERSION_ATTR,
                               SYSDB_GPO_SYSVOL_VERSION_ATTR,
                               SYSDB_GPO_TIMEOUT_ATTR,
                               NULL};
    struct ldb_message_element *el;
    struct test_data *data;
    const char *gpo_cse_guid;
    time_t now;
    errno_t ret;
    int lret;

    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);
    data = test_ctx->data;
    gpo_cse_guid = data->linked_gpos[0]->gpo_cse_guids[0],

    check_leaks_push(test_ctx);
    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);
    assert_int_equal(test_ctx->data->msg->num_elements, 1);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 3);

    talloc_free(data->msg);

    ret = sysdb_gpo_cse_search(test_ctx,
                               test_ctx->tctx->dom,
                               gpo_cse_guid,
                               gpo_cse_attrs,
                               &data->msgs_count,
                               &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);

    talloc_free(data->msgs);
    assert_true(check_leaks_pop(test_ctx) == true);

    ret = sysdb_gpo_cse_search_parent_gpo(test_ctx,
                                          test_ctx->tctx->dom,
                                          gpo_cse_guid,
                                          gpo_attrs,
                                          &data->msgs_count,
                                          &data->msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(data->msgs_count, 3);

    ret = sysdb_delete_entry(test_ctx->tctx->dom->sysdb,
                             data->msgs[2]->dn,
                             false);
    assert_int_equal(ret, EOK);

    talloc_free(data->msgs);

    check_leaks_push(test_ctx);
    data->res = NULL;
    ret = sysdb_gpo_get_gpo_by_guid(test_ctx,
                                    test_ctx->tctx->dom,
                                    data->linked_gpos[2]->gpo_guid,
                                    gpo_attrs,
                                    &data->res);
    assert_int_equal(ret, ENOENT);
    assert_null(data->res);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, ENOENT);

    now = time(NULL);
    ret = sysdb_gpo_store_gpo(test_ctx->tctx->dom,
                              data->linked_gpos[2]->gpo_guid,
                              data->linked_gpos[2]->gpo_dn,
                              data->linked_gpos[2]->gpo_display_name,
                              data->linked_gpos[2]->gpo_container_version,
                              data->linked_gpos[2]->gpo_file_system_version,
                              5, now);
    assert_int_equal(ret, EOK);

    ret = ad_gpo_cache_refresh_status(test_ctx->tctx->dom,
                                      AD_GP_MODE_COMPUTER,
                                      gpo_cse_guid,
                                      test_ctx->data->gpo_cse_dn_list,
                                      test_ctx->data->num_linked_gpos);
    assert_int_equal(ret, EOK);

    assert_true(check_leaks_pop(test_ctx) == true);
}

void test_store_computer(void **state)
{
    const char *attrs[] = {SYSDB_NAME, SYSDB_SID_STR, SYSDB_MEMBEROF_SID_STR,
                           SYSDB_ORIG_DN, SYSDB_GPLINK_STR,
                           SYSDB_CACHE_EXPIRE, SYSDB_CREATE_TIME,
                           NULL};
    struct ldb_message_element *el;
    const char *value_str;
    time_t value_time;
    int lret;
    int i;
    struct computer_test_ctx *test_ctx =
            talloc_get_type_abort(*state, struct computer_test_ctx);

    check_leaks_push(test_ctx);
    lret = sysdb_set_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              test_ctx->data->host_dn,
                              test_ctx->data->host_sid,
                              test_ctx->data->host_group_sids,
                              test_ctx->data->num_host_groups,
                              0, 0);
    assert_int_equal(lret, EOK);

    lret = sysdb_get_computer(test_ctx,
                              test_ctx->tctx->dom,
                              test_ctx->data->hostname,
                              attrs,
                              &test_ctx->data->msg);
    assert_int_equal(lret, EOK);
    assert_non_null(test_ctx->data->msg);

    value_str = ldb_msg_find_attr_as_string(test_ctx->data->msg,
                                            SYSDB_NAME, NULL);
    assert_string_equal(value_str, test_ctx->data->hostname);

    value_str = ldb_msg_find_attr_as_string(test_ctx->data->msg,
                                            SYSDB_SID_STR, NULL);
    assert_string_equal(value_str, test_ctx->data->host_sid);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_MEMBEROF_SID_STR);
    assert_non_null(el);
    assert_int_equal(el->num_values, 2);
    for (i=0; i<el->num_values; i++) {
        assert_true(is_in_list(test_ctx->data->host_group_sids,
                               test_ctx->data->num_host_groups,
                               (char *)el->values[i].data));
    }

    value_str = ldb_msg_find_attr_as_string(test_ctx->data->msg,
                                            SYSDB_ORIG_DN, NULL);
    assert_string_equal(value_str, test_ctx->data->host_dn);

    el = ldb_msg_find_element(test_ctx->data->msg, SYSDB_GPLINK_STR);
    assert_null(el);

    value_time = ldb_msg_find_attr_as_uint64(test_ctx->data->msg,
                                             SYSDB_CACHE_EXPIRE, 0);
    assert_int_equal(value_time, 0);

    value_time = ldb_msg_find_attr_as_uint64(test_ctx->data->msg,
                                             SYSDB_CREATE_TIME, 0);
    assert_int_equal(value_time, 0);

    talloc_free(test_ctx->data->msg);
    assert_true(check_leaks_pop(test_ctx) == true);
}

int main(int argc, const char** argv) {
    int rv;
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_store_computer),
        cmocka_unit_test(test_modify_computer_group),
        cmocka_unit_test(test_modify_computer_sid),
        cmocka_unit_test(test_store_gp_links),
        cmocka_unit_test(test_modify_gp_links),
        cmocka_unit_test(test_remove_gp_links),
        cmocka_unit_test(test_check_gpo_cache_status_no_gpo),
        cmocka_unit_test(test_check_gpo_cache_status_no_refresh),
        cmocka_unit_test(test_check_gpo_cache_status_fs_version_change),
        cmocka_unit_test(test_check_gpo_cache_status_ad_version_change),
        cmocka_unit_test(test_check_gpo_cache_status_user_version_change),
        cmocka_unit_test(test_check_gpo_cache_status_timeout),
        cmocka_unit_test(test_check_gpo_cache_status_gp_links),
        cmocka_unit_test(test_check_gpo_cache_status_cse_gpo)
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, NULL);
    rv = cmocka_run_group_tests(tests,
                                test_sysdb_computer_setup,
                                test_sysdb_computer_teardown);

    if (rv == 0 && no_cleanup == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, NULL);
    }
    return rv;
}
