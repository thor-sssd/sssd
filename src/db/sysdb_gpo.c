/*
    SSSD

    Authors:
        Yassir Elley <yelley@redhat.com>

    Copyright (C) 2014 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "db/sysdb.h"
#include "db/sysdb_private.h"

static struct ldb_dn *
sysdb_gpo_dn(TALLOC_CTX *mem_ctx, struct sss_domain_info *domain,
             const char *gpo_guid)
{
    errno_t ret;
    char *clean_gpo_guid;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, gpo_guid, &clean_gpo_guid);
    if (ret != EOK) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO"\n", clean_gpo_guid, domain->name);

    dn = ldb_dn_new_fmt(mem_ctx, domain->sysdb->ldb, SYSDB_TMPL_GPO,
                        clean_gpo_guid, domain->name);
    talloc_free(clean_gpo_guid);

    return dn;
}

errno_t
sysdb_gpo_store_gpo(struct sss_domain_info *domain,
                    const char *gpo_guid,
                    const char *gpo_dn,
                    const char *gpo_name,
                    int gpo_ad_version,
                    int gpo_sysvol_version,
                    int cache_timeout,
                    time_t now)
{
    errno_t ret, sret;
    int lret;
    struct ldb_message *update_msg;
    struct ldb_message **msgs;
    static const char *attrs[] = SYSDB_GPO_ATTRS;
    size_t count;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    update_msg = ldb_msg_new(tmp_ctx);
    if (!update_msg) {
        ret = ENOMEM;
        goto done;
    }

    update_msg->dn = sysdb_gpo_dn(update_msg, domain, gpo_guid);
    if (!update_msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    if (!now) {
        now = time(NULL);
    }

    in_transaction = true;

    /* Check for an existing gpo_guid entry */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, update_msg->dn,
                             LDB_SCOPE_BASE, NULL, attrs, &count, &msgs);

    if (ret == ENOENT) {
        /* Create new GPO */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Adding new GPO [gpo_guid:%s][gpo_version:%d(AD),%d(sysvol)]\n",
              gpo_guid, gpo_ad_version, gpo_sysvol_version);

        /* Add the objectClass */
        lret = ldb_msg_add_empty(update_msg, SYSDB_OBJECTCLASS,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_OBJECTCLASS,
                                  SYSDB_GPO_OC);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Add the GPO GUID */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_GUID_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_GPO_GUID_ATTR, gpo_guid);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Add the original GPO DN */
        lret = ldb_msg_add_empty(update_msg, SYSDB_ORIG_DN,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_ORIG_DN, gpo_dn);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Add GPO name */
        lret = ldb_msg_add_empty(update_msg, SYSDB_NAME,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_NAME, gpo_name);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Add GPO container version */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_AD_VERSION_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_AD_VERSION_ATTR,
                               "%d", gpo_ad_version);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Add GPO file system version */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_SYSVOL_VERSION_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_SYSVOL_VERSION_ATTR,
                               "%d", gpo_sysvol_version);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Add the Policy File Timeout */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_TIMEOUT_ATTR,
                                 LDB_FLAG_MOD_ADD, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_TIMEOUT_ATTR, "%lu",
                               ((cache_timeout) ? (now + cache_timeout) : 0));
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_add(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to add GPO: [%s]\n",
                   ldb_strerror(lret));
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }
    } else if (ret == EOK && count == 1) {
        DEBUG(SSSDBG_TRACE_ALL, "Updating GPO [%s][%s]\n",
              domain->name, gpo_guid);

        /* Update GPO display name */
        lret = ldb_msg_add_empty(update_msg, SYSDB_NAME,
                                 LDB_FLAG_MOD_REPLACE,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_NAME, gpo_name);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Update original GPO DN */
        lret = ldb_msg_add_empty(update_msg, SYSDB_ORIG_DN,
                                 LDB_FLAG_MOD_REPLACE,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_ORIG_DN, gpo_dn);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Update GPO container version */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_AD_VERSION_ATTR,
                                 LDB_FLAG_MOD_REPLACE,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_AD_VERSION_ATTR,
                               "%d", gpo_ad_version);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Update GPO file system version */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_SYSVOL_VERSION_ATTR,
                                 LDB_FLAG_MOD_REPLACE,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_SYSVOL_VERSION_ATTR,
                               "%d", gpo_sysvol_version);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Update Policy File Timeout */
        lret = ldb_msg_add_empty(update_msg, SYSDB_GPO_TIMEOUT_ATTR,
                                 LDB_FLAG_MOD_REPLACE, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_GPO_TIMEOUT_ATTR, "%lu",
                               ((cache_timeout) ? (now + cache_timeout) : 0));
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_modify(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to modify GPO: [%s](%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(domain->sysdb->ldb));
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }
    } else {
        ret = EIO;
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not commit transaction: [%s]\n", strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_gpo_get_gpo_by_guid(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          const char *gpo_guid,
                          const char **attrs,
                          struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO_BASE"\n", domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_GPO_BASE,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_GPO_GUID_FILTER, gpo_guid);
    if (lret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not locate GPO: [%s]\n",
              ldb_strerror(lret));
        ret = sss_ldb_error_to_errno(lret);
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Search for GUID [%s] returned more than " \
              "one object.\n", gpo_guid);
        ret = EINVAL;
        goto done;
    } else if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }
    *_result = talloc_steal(mem_ctx, res);
    ret = EOK;
done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No such entry.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_gpo_get_gpos(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char **attrs,
                   struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO_BASE"\n", domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_GPO_BASE,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_GPO_FILTER);
    if (lret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not locate GPOs: [%s]\n",
              ldb_strerror(lret));
        ret = sss_ldb_error_to_errno(lret);
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    *_result = talloc_steal(mem_ctx, res);
    ret = EOK;

done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No GPO entries.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}

/* CSE */

static struct ldb_dn *
sysdb_gpo_cse_dn(TALLOC_CTX *mem_ctx, struct sss_domain_info *domain,
                 const char *gpo_guid, const char *cse_guid)
{
    errno_t ret;
    char *clean_gpo_guid;
    char *clean_cse_guid;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, gpo_guid, &clean_gpo_guid);
    if (ret != EOK) {
        return NULL;
    }

    ret = sysdb_dn_sanitize(NULL, cse_guid, &clean_cse_guid);
    if (ret != EOK) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_CSE"\n",
          clean_cse_guid, clean_gpo_guid, domain->name);

    dn = ldb_dn_new_fmt(mem_ctx, domain->sysdb->ldb, SYSDB_TMPL_CSE,
                        clean_cse_guid, clean_gpo_guid, domain->name);
    talloc_free(clean_gpo_guid);
    talloc_free(clean_cse_guid);

    return dn;
}

errno_t
sysdb_gpo_cse_search(TALLOC_CTX *mem_ctx, struct sss_domain_info *domain,
                     const char *cse_guid, const char **attrs,
                     size_t *_num_gpos,
                     struct ldb_message ***_gpos)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn;
    const char * filter;
    struct ldb_message **results;
    size_t num_results;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_base_dn(domain->sysdb, tmp_ctx);
    if (!basedn) {
        return ENOMEM;
    }
    filter = talloc_asprintf(tmp_ctx, SYSDB_CSE_GUID_FILTER, cse_guid);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, filter, attrs,
                             &num_results, &results);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC, "No such CSE %s in cache\n", cse_guid);
            *_gpos = NULL;
            *_num_gpos = 0;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Error looking up CSE %s [%d]: %s\n",
                  cse_guid, ret, strerror(ret));
        }
        goto done;
    }

    *_gpos = talloc_steal(mem_ctx, results);
    *_num_gpos = num_results;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_gpo_cse_search_parent_gpo(TALLOC_CTX *mem_ctx, struct sss_domain_info *domain,
                                const char *cse_guid, const char **attrs,
                                size_t *_num_gpos,
                                struct ldb_message ***_gpos)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn;
    const char * cse_attrs[] = {NULL};
    const char * filter;
    struct ldb_dn *gpo_dn;
    struct ldb_message **cse_results;
    struct ldb_message **gpo_results;
    struct ldb_message **gpo_result_list;
    size_t num_cse_results;
    size_t num_gpo_results;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    basedn = sysdb_base_dn(domain->sysdb, tmp_ctx);
    if (!basedn) {
        return ENOMEM;
    }
    filter = talloc_asprintf(tmp_ctx, SYSDB_CSE_GUID_FILTER, cse_guid);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, filter, cse_attrs,
                             &num_cse_results, &cse_results);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC, "No such CSE %s in cache\n", cse_guid);
            *_gpos = NULL;
            *_num_gpos = 0;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Error looking up CSE %s [%d]: %s\n",
                  cse_guid, ret, strerror(ret));
        }
        goto done;
    }
    gpo_result_list = talloc_array(tmp_ctx,
                                   struct ldb_message *,
                                   num_cse_results + 1);
    if (gpo_result_list == NULL) {
        ret = ENOMEM;
        goto done;
    }
    for (i = 0; i < num_cse_results; i++) {
        /* Look for existing GPO entry in cache */
        gpo_dn = ldb_dn_get_parent(tmp_ctx, cse_results[i]->dn);
        if (gpo_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "No parent GPO entry for CSE %s\n",
                  ldb_dn_get_linearized(cse_results[i]->dn));
            ret = EINVAL;
            goto done;
        }
        ret = sysdb_search_entry(tmp_ctx, domain->sysdb, gpo_dn,
                                 LDB_SCOPE_BASE, NULL, attrs,
                                 &num_gpo_results, &gpo_results);
        if (ret == ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "No cache entry for parent GPO of CSE entry %s\n",
                  ldb_dn_get_linearized(cse_results[i]->dn));
            goto done;
        }
        if (ret == EOK) {
            if (ret == EOK && num_gpo_results == 1) {
                gpo_result_list[i] = talloc_steal(gpo_result_list, gpo_results[0]);
            } else {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Multiple parent GPO cache entries for CSE entry %s\n",
                      ldb_dn_get_linearized(cse_results[i]->dn));
                ret = EINVAL;
                goto done;
            }
        } else {
            goto done;
        }
    }

    *_gpos = talloc_steal(mem_ctx, gpo_result_list);
    *_num_gpos = num_cse_results;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_gpo_store_cse(struct sss_domain_info *domain,
                    const char *gpo_guid,
                    const char *cse_guid,
                    int cse_version,
                    int cache_timeout,
                    time_t now)
{
    errno_t ret, sret;
    int lret;
    struct ldb_message *update_msg;
    struct ldb_message **msgs;
    static const char *attrs[] = SYSDB_CSE_ATTRS;
    size_t count;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    update_msg = ldb_msg_new(tmp_ctx);
    if (!update_msg) {
        ret = ENOMEM;
        goto done;
    }

    update_msg->dn = sysdb_gpo_cse_dn(update_msg, domain, gpo_guid, cse_guid);
    if (!update_msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    if (!now) {
        now = time(NULL);
    }

    in_transaction = true;

    /* Check for an existing gpo_guid/cse_guid entry */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, update_msg->dn,
                             LDB_SCOPE_BASE, NULL, attrs, &count, &msgs);

    if (ret == ENOENT) {
        /* Create new CSE */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Adding new CSE [cse_guid:%s] for GPO [gpo_guid:%s]\n",
              cse_guid, gpo_guid);

        /* Add the objectClass */
        lret = ldb_msg_add_empty(update_msg, SYSDB_OBJECTCLASS,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_OBJECTCLASS,
                                  SYSDB_CSE_OC);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the CSE GUID */
        lret = ldb_msg_add_empty(update_msg, SYSDB_CSE_GUID_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_CSE_GUID_ATTR, cse_guid);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the Version */
        lret = ldb_msg_add_empty(update_msg, SYSDB_CSE_VERSION_ATTR,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_CSE_VERSION_ATTR,
                               "%d", cse_version);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the Policy File Timeout */
        lret = ldb_msg_add_empty(update_msg, SYSDB_CSE_TIMEOUT_ATTR,
                                 LDB_FLAG_MOD_ADD, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_CSE_TIMEOUT_ATTR, "%lu",
                               ((cache_timeout) ? (now + cache_timeout) : 0));
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_add(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to add CSE: [%s]\n",
                   ldb_strerror(lret));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else if (ret == EOK && count == 1) {
        /* Update the existing CSE */

        DEBUG(SSSDBG_TRACE_ALL, "Updating CSE [%s] for GPO [%s][%s]\n",
              cse_guid, domain->name, gpo_guid);

        /* Add the Version */
        lret = ldb_msg_add_empty(update_msg, SYSDB_CSE_VERSION_ATTR,
                                 LDB_FLAG_MOD_REPLACE,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_CSE_VERSION_ATTR,
                               "%d", cse_version);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        /* Add the Policy File Timeout */
        lret = ldb_msg_add_empty(update_msg, SYSDB_CSE_TIMEOUT_ATTR,
                                 LDB_FLAG_MOD_REPLACE, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_fmt(update_msg, SYSDB_CSE_TIMEOUT_ATTR, "%lu",
                               ((cache_timeout) ? (now + cache_timeout) : 0));
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_modify(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to modify CSE: [%s](%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(domain->sysdb->ldb));
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else {
        ret = EIO;
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not commit transaction: [%s]\n", strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sysdb_gpo_cse_purge_parent_gpos(struct sss_domain_info *domain,
                                const char *cse_guid,
                                struct ldb_dn **parent_gpo_dn_list,
                                size_t parent_gpo_count)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct ldb_result *res;
    struct ldb_message **msgs;
    struct ldb_message_element *el;
    size_t count;
    const char *gpo_attrs[] = {SYSDB_GPO_GUID_ATTR, SYSDB_GPO_TIMEOUT_ATTR,
                               NULL};
    const char *cse_attrs[] = {NULL};
    const char *gpo_guid;
    time_t policy_file_timeout;

    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Simple GPO cache garbadge collection management:
     * Walk through the list of parent GPO entries that contained the deleted
     * client-side extension. Remove obsolete parent GPO entries from cache.
     * Obsolescence criteria for parent GPO entries:
     * - GPO contains no other client-side extensions (CSE)
     * - GPO timeout is set
     * - GPO has expired
     */
    for (i = 0; i < parent_gpo_count; i++) {
        /* Look for existing GPO entry in cache */
        if (parent_gpo_dn_list[i] == NULL) continue;
        ret = sysdb_search_entry(tmp_ctx, domain->sysdb, parent_gpo_dn_list[i],
                                 LDB_SCOPE_BASE, NULL, gpo_attrs,
                                 &count, &msgs);
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "No cache entry for parent GPO %s\n",
                  ldb_dn_get_linearized(parent_gpo_dn_list[i]));
            continue;
        }
        if (ret == EOK && count == 1) {
            el = ldb_msg_find_element(msgs[0], SYSDB_GPO_GUID_ATTR);
            if (el != NULL) {
                gpo_guid = ldb_msg_find_attr_as_string(msgs[0],
                                                       SYSDB_GPO_GUID_ATTR,
                                                       NULL);
            }
            if (el == NULL || gpo_guid == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Missing %s attribute in parent GPO %s\n",
                      SYSDB_GPO_GUID_ATTR,
                      ldb_dn_get_linearized(parent_gpo_dn_list[i]));
                continue;
            }
            el = ldb_msg_find_element(msgs[0], SYSDB_GPO_TIMEOUT_ATTR);
            if (el != NULL) {
                policy_file_timeout =
                    ldb_msg_find_attr_as_uint64(msgs[0],
                                                SYSDB_GPO_TIMEOUT_ATTR, 0);
            } else {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Missing %s attribute in parent GPO %s\n",
                      SYSDB_GPO_TIMEOUT_ATTR,
                      ldb_dn_get_linearized(parent_gpo_dn_list[i]));
                continue;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up parent GPO %s\n",
                  ldb_dn_get_linearized(parent_gpo_dn_list[i]));
            ret = ret ? ret : EINVAL;
            goto done;
        }
        if (policy_file_timeout < time(NULL)) {
            ret = sysdb_gpo_get_cses(tmp_ctx,
                                     domain,
                                     gpo_guid,
                                     cse_attrs,
                                     &res);
            if (ret == EOK) {
                // GPO has further CSEs; leave it in cache
                continue;
            }
            else if (ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Error looking up CSEs of parent GPO %s\n",
                      ldb_dn_get_linearized(parent_gpo_dn_list[i]));
                goto done;
            }
            // Expired GPO with no CSE: delete it from cache
            ret = sysdb_delete_entry(domain->sysdb,
                                     parent_gpo_dn_list[i],
                                     false);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to delete GPO %s [%d]: %s\n",
                      ldb_dn_get_linearized(parent_gpo_dn_list[i]),
                      ret, sss_strerror(ret));
                continue;
            }
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Removed empty parent GPO [gpo_guid:%s] from cache\n",
                  gpo_guid);
        }
    }
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sysdb_gpo_cse_purge_all(struct sss_domain_info *domain,
                        const char *cse_guid)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct ldb_message **msgs;
    size_t count;
    struct ldb_dn **gpo_dn_list;
    int gpo_dn_idx = 0;
    int i;

    const char *attrs[] = {NULL};

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sysdb_gpo_cse_search(tmp_ctx,
                               domain, cse_guid, attrs,
                               &count,
                               &msgs);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No GPO CSE %s in cache\n", cse_guid);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up GPO CSE %s [%d]: %s",
                                   cse_guid, ret, strerror(ret));
        goto done;
    }

    gpo_dn_list = talloc_array(tmp_ctx,
                               struct ldb_dn *,
                               count + 1);
    if (gpo_dn_list == NULL) {
        ret = ENOMEM;
        goto done;
    }
    for (i = 0; i < count; i++) {
        gpo_dn_list[i] = ldb_dn_get_parent(tmp_ctx, msgs[i]->dn);
        ret = sysdb_delete_entry(domain->sysdb, msgs[i]->dn, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to delete GPO CSE "
                  "%s [%d]: %s\n",
                  ldb_dn_get_linearized(msgs[i]->dn), ret, sss_strerror(ret));
            continue;
        }
        gpo_dn_idx++;
    }

    ret = sysdb_gpo_cse_purge_parent_gpos(domain,
                                          cse_guid,
                                          gpo_dn_list,
                                          gpo_dn_idx);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sysdb_gpo_cse_purge_byfilter(struct sss_domain_info *domain,
                             const char *cse_guid,
                             const char *filter)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn;
    struct ldb_dn **gpo_dn_list;
    struct ldb_message **msgs;
    struct ldb_message_element *el;
    const char *gpo_cse_guid;
    const char *oc;
    size_t value_len;
    size_t count;
    errno_t ret;
    int gpo_dn_idx = 0;
    int i;
    const char *attrs[] = { SYSDB_OBJECTCLASS,
                            SYSDB_CSE_GUID_ATTR,
                            NULL };

    if (filter == NULL || strcmp(filter, SYSDB_CSE_GUID_FILTER) == 0) {
        return sysdb_gpo_cse_purge_all(domain, cse_guid);
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    basedn = sysdb_base_dn(domain->sysdb, tmp_ctx);
    if (!basedn) {
        return ENOMEM;
    }
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, filter, attrs,
                             &count, &msgs);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No orphan GPO CSE %s in cache\n", cse_guid);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up GPO CSE %s [%d]: %s",
                                   cse_guid, ret, strerror(ret));
        goto done;
    }
    gpo_dn_list = talloc_array(tmp_ctx,
                               struct ldb_dn *,
                               count + 1);
    if (gpo_dn_list == NULL) {
        ret = ENOMEM;
        goto done;
    }
    for (i = 0; i < count; i++) {
        el = ldb_msg_find_element(msgs[0], SYSDB_OBJECTCLASS);
        if (el != NULL) {
            oc = ldb_msg_find_attr_as_string(msgs[i],
                                             SYSDB_OBJECTCLASS,
                                             NULL);
            if (oc != NULL) {
                value_len = strlen(oc);
                if (value_len != strlen(SYSDB_CSE_OC) ||
                    strncasecmp(oc, SYSDB_CSE_OC, value_len) != 0) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "Matched cache object %s not a GPO CSE\n",
                          ldb_dn_get_linearized(msgs[i]->dn));
                    continue;
                }
            }
        }
        if (el == NULL || oc == NULL) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Matched cache object %s not a GPO CSE? Missing %s\n",
                  ldb_dn_get_linearized(msgs[i]->dn), SYSDB_OBJECTCLASS);
            continue;
        }
        el = ldb_msg_find_element(msgs[0], SYSDB_CSE_GUID_ATTR);
        if (el != NULL) {
            gpo_cse_guid = ldb_msg_find_attr_as_string(msgs[i],
                                                       SYSDB_CSE_GUID_ATTR,
                                                       NULL);
            if (gpo_cse_guid != NULL) {
                value_len = strlen(gpo_cse_guid);
                if (value_len != strlen(cse_guid) ||
                    strncasecmp(gpo_cse_guid, cse_guid, value_len) != 0) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "Matched cache object %s not a GPO CSE %s\n",
                          ldb_dn_get_linearized(msgs[i]->dn), cse_guid);
                    continue;
                }
            }
        }
        if (el == NULL || gpo_cse_guid == NULL) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Missing %s attribute in GPO CSE %s\n",
                  SYSDB_CSE_GUID_ATTR, ldb_dn_get_linearized(msgs[i]->dn));
            continue;
        }
        gpo_dn_list[gpo_dn_idx] = ldb_dn_get_parent(tmp_ctx, msgs[i]->dn);
        ret = sysdb_delete_entry(domain->sysdb, msgs[i]->dn, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to delete GPO CSE "
                  "%s [%d]: %s\n",
                  ldb_dn_get_linearized(msgs[i]->dn), ret, sss_strerror(ret));
            continue;
        }
        gpo_dn_idx++;
    }
    if (gpo_dn_idx == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No GPO CSE %s matched\n", cse_guid);
        ret = EOK;
        goto done;
    }

    ret = sysdb_gpo_cse_purge_parent_gpos(domain,
                                          cse_guid,
                                          gpo_dn_list,
                                          gpo_dn_idx);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_gpo_cse_purge(struct sss_domain_info *domain,
                            const char *cse_guid,
                            const char *delete_filter)
{
    bool in_transaction = false;
    errno_t sret;
    errno_t ret;

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        return ret;
    }
    in_transaction = true;

    if (delete_filter) {
        ret = sysdb_gpo_cse_purge_byfilter(domain, cse_guid, delete_filter);
    } else {
        ret = sysdb_gpo_cse_purge_all(domain, cse_guid);
    }

    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to purge GPO CSE cache [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

errno_t
sysdb_gpo_get_cse_by_guid(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          const char *gpo_guid,
                          const char *cse_guid,
                          const char **attrs,
                          struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO"\n", gpo_guid, domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb, SYSDB_TMPL_GPO,
                             gpo_guid,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_CSE_GUID_FILTER, cse_guid);
    if (lret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not locate CSE: [%s]\n",
              ldb_strerror(lret));
        ret = sss_ldb_error_to_errno(lret);
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Search for GUID [%s] returned more than " \
              "one object.\n", cse_guid);
        ret = EINVAL;
        goto done;
    } else if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }
    *_result = talloc_steal(mem_ctx, res);
    ret = EOK;
done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No such entry.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_gpo_get_cses(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *gpo_guid,
                   const char **attrs,
                   struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GPO"\n",
          gpo_guid, domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_GPO,
                             gpo_guid,
                             domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_CSE_FILTER);
    if (lret) {
        ret = sss_ldb_error_to_errno(lret);
        goto done;
    }
    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    *_result = talloc_steal(mem_ctx, res);
    ret = EOK;

done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No CSE entries in cache.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}

/* Group Policy (GP) Result */

static struct ldb_dn *
sysdb_gpo_gp_result_dn(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *cse_guid)
{
    errno_t ret;
    char *clean_cse_guid;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, cse_guid, &clean_cse_guid);
    if (ret != EOK) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GP_RESULT"\n",
          clean_cse_guid, domain->name);

    dn = ldb_dn_new_fmt(mem_ctx, domain->sysdb->ldb, SYSDB_TMPL_GP_RESULT,
                        clean_cse_guid, domain->name);
    talloc_free(clean_cse_guid);

    return dn;
}

errno_t
sysdb_gpo_store_gp_result_setting(struct sss_domain_info *domain,
                                  const char *cse_guid,
                                  const char *ini_key,
                                  const char *ini_value)
{
    errno_t ret, sret;
    int lret;
    struct ldb_message *update_msg;
    struct ldb_message **msgs;
    size_t count;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    update_msg = ldb_msg_new(tmp_ctx);
    if (!update_msg) {
        ret = ENOMEM;
        goto done;
    }

    update_msg->dn = sysdb_gpo_gp_result_dn(update_msg, domain, cse_guid);
    if (!update_msg->dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    /* Check for an existing GP Result object */
    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, update_msg->dn,
                             LDB_SCOPE_BASE, NULL, NULL, &count, &msgs);

    if (ret == ENOENT) {
        /* Create new GP Result object */
        DEBUG(SSSDBG_TRACE_FUNC, "Storing setting: key [%s] value [%s]\n",
              ini_key, ini_value);

        /* Add the objectClass */
        lret = ldb_msg_add_empty(update_msg, SYSDB_OBJECTCLASS,
                                 LDB_FLAG_MOD_ADD,
                                 NULL);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        lret = ldb_msg_add_string(update_msg, SYSDB_OBJECTCLASS,
                                  SYSDB_GP_RESULT_OC);
        if (lret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }

        /* Store the policy_setting if it is non-NULL */
        if (ini_value) {
            lret = ldb_msg_add_empty(update_msg, ini_key,
                                     LDB_FLAG_MOD_ADD,
                                     NULL);
            if (lret != LDB_SUCCESS) {
                ret = sss_ldb_error_to_errno(lret);
                goto done;
            }

            lret = ldb_msg_add_string(update_msg, ini_key, ini_value);
            if (lret != LDB_SUCCESS) {
                ret = sss_ldb_error_to_errno(lret);
                goto done;
            }
        }

        lret = ldb_add(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to add GP Result: [%s]\n",
                   ldb_strerror(lret));
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }
    } else if (ret == EOK && count == 1) {
        /* Update existing GP Result object*/
        if (ini_value) {
            DEBUG(SSSDBG_TRACE_FUNC, "Updating setting: key [%s] value [%s]\n",
                  ini_key, ini_value);
            /* Update the policy setting */
            lret = ldb_msg_add_empty(update_msg, ini_key,
                                     LDB_FLAG_MOD_REPLACE,
                                     NULL);
            if (lret != LDB_SUCCESS) {
                ret = sss_ldb_error_to_errno(lret);
                goto done;
            }

            lret = ldb_msg_add_fmt(update_msg, ini_key, "%s", ini_value);
            if (lret != LDB_SUCCESS) {
                ret = sss_ldb_error_to_errno(lret);
                goto done;
            }
        } else {
            /* If the value is NULL, we need to remove it from the cache */
            DEBUG(SSSDBG_TRACE_FUNC, "Removing setting: key [%s]\n", ini_key);

            /* Update the policy setting */
            lret = ldb_msg_add_empty(update_msg, ini_key,
                                     LDB_FLAG_MOD_DELETE,
                                     NULL);
            if (lret != LDB_SUCCESS) {
                ret = sss_ldb_error_to_errno(lret);
                goto done;
            }
        }

        lret = ldb_modify(domain->sysdb->ldb, update_msg);
        if (lret != LDB_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to modify GP Result: [%s](%d)[%s]\n",
                  ldb_strerror(lret), lret, ldb_errstring(domain->sysdb->ldb));
            ret = sss_ldb_error_to_errno(lret);
            goto done;
        }
    } else {
        ret = EIO;
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not commit transaction: [%s]\n", strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sysdb_gpo_get_gp_result_object(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               const char *cse_guid,
                               const char **attrs,
                               struct ldb_result **_result)
{
    errno_t ret;
    int lret;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_ALL, SYSDB_TMPL_GP_RESULT"\n", cse_guid, domain->name);

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_GP_RESULT,
                             cse_guid, domain->name);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, base_dn,
                      LDB_SCOPE_SUBTREE, attrs, SYSDB_GP_RESULT_FILTER);
    if (lret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not locate GP Result object: [%s]\n",
              ldb_strerror(lret));
        ret = sss_ldb_error_to_errno(lret);
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    *_result = talloc_steal(mem_ctx, res);
    ret = EOK;

done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No GP Result object in cache.\n");
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}


errno_t
sysdb_gpo_get_gp_result_setting(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *cse_guid,
                                 const char *ini_key,
                                 const char **_ini_value)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    const char *ini_value;

    const char *attrs[] = {ini_key, NULL};

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sysdb_gpo_get_gp_result_object(tmp_ctx,
                                         domain,
                                         cse_guid,
                                         attrs,
                                         &res);
    if (ret != EOK) {
        goto done;
    }

    ini_value = ldb_msg_find_attr_as_string(res->msgs[0],
                                            ini_key,
                                            NULL);
    DEBUG(SSSDBG_TRACE_FUNC, "key [%s] value [%s]\n", ini_key, ini_value);

    *_ini_value = talloc_strdup(mem_ctx, ini_value);
    if (!*_ini_value && ini_value) {
        /* If ini_value was NULL, this is expected to also be NULL */
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:

    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No setting for key [%s].\n", ini_key);
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);
    return ret;
}


errno_t sysdb_gpo_delete_gp_result_object(TALLOC_CTX *mem_ctx,
                                          struct sss_domain_info *domain,
                                          const char *cse_guid)
{
    struct ldb_result *res;
    errno_t ret, sret;
    bool in_transaction = false;

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    ret = sysdb_gpo_get_gp_result_object(mem_ctx, domain, cse_guid, NULL, &res);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not delete GP result object: %d\n", ret);
        goto done;
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "Deleting GP Result object\n");

        ret = sysdb_delete_entry(domain->sysdb, res->msgs[0]->dn, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not delete GP Result cache entry\n");
            goto done;
        }
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not commit transaction: [%s]\n", strerror(ret));
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    return ret;

}
