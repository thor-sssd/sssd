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

        /* Add GPO container version */
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

        /* Add GPO file system version */
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

        /* Add the Policy File Timeout */
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
