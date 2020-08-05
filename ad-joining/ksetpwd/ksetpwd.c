//
// Copyright 2019 Google LLC
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//

#include <stdio.h>
#include <locale.h>
#include <sys/types.h>
#include <krb5.h>

#define NAME "ksetpwd"

static int authenticate_agent(
    /* [IN] */ krb5_context context,
    /* [IN] */ krb5_principal agent_principal,
    /* [IN, OPT] */ char *agent_principal_password,
    /* [OUT] */ krb5_creds *agent_creds)
{
    int result;
    krb5_get_init_creds_opt *opts;

    result = krb5_get_init_creds_opt_alloc(context, &opts);
    if (result)
    {
        com_err(NAME, result, "Initializing options failed");
        return 1;
    }

    krb5_get_init_creds_opt_set_tkt_life(opts, 5 * 60);
    krb5_get_init_creds_opt_set_renew_life(opts, 0);
    krb5_get_init_creds_opt_set_forwardable(opts, 0);
    krb5_get_init_creds_opt_set_proxiable(opts, 0);

    result = krb5_get_init_creds_password(
        context,
        agent_creds,
        agent_principal,
        agent_principal_password,
        krb5_prompter_posix,
        NULL,
        0,
        "kadmin/changepw",
        opts);

    krb5_get_init_creds_opt_free(context, opts);

    return result;
}

static int reset_password(
    /* [IN] */ krb5_context context,
    /* [IN] */ krb5_principal agent_principal,
    /* [IN, OPT] */ char *agent_principal_password,
    /* [IN] */ krb5_principal target_principal,
    /* [IN] */ char* new_password)
{
    krb5_error_code ret;
    krb5_creds agent_creds;
    int result;

    char* message = NULL;
    int server_result = 0;
    krb5_data server_result_string = {0};
    krb5_data server_result_code_string = {0};

    // Get initial credentials for agent.
    result = authenticate_agent(context, agent_principal, agent_principal_password, &agent_creds);
    if (result != 0)
    {
        if (result == KRB5KRB_AP_ERR_BAD_INTEGRITY)
        {
            com_err(NAME, 0, "Invalid password for agent principal");
        }
        else {
            com_err(NAME, ret, "Authenticating agent principal failed");
        }

        goto cleanup;
    }

    // Reset password of target principal.
    result = krb5_set_password(
        context,
        &agent_creds,
        new_password,
        target_principal,
        &server_result,
        &server_result_code_string,
        &server_result_string);
    if (result != 0)
    {
        com_err(NAME, ret, "Resetting password failed");
        goto cleanup;
    }

    if (server_result)
    {
        if (krb5_chpw_message(context, &server_result_string, &message) != 0)
        {
            message = NULL;
        }

        fprintf(stderr, "%.*s%s%s\n",
            (int)server_result_code_string.length,
            server_result_code_string.data,
            message ? ": " : "",
            message ? message : NULL);

        result = KRB5_KPASSWD_SOFTERROR;
        goto cleanup;
    }

    printf("Password changed.\n");

cleanup:
    if (message != NULL)
    {
        krb5_free_string(context, message);
    }

    if (server_result_string.data != NULL)
    {
        free(server_result_string.data);
    }

    if (server_result_code_string.data != NULL)
    {
        free(server_result_code_string.data);
    }

    return result;
}


int main(
    /* [IN] */ int argc,
    /* [IN] */ char *argv[])
{
    int result;
    krb5_context context = NULL;
    krb5_principal agent_principal = NULL;
    krb5_principal target_principal = NULL;

    // Parse command line
    setlocale(LC_ALL, "");
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s [agent principal] [principal]\n", NAME);
        result = 1;
        goto cleanup;
    }

    // Initialize Kerberos.
    result = krb5_init_context(&context);
    if (result != 0)
    {
        com_err(NAME, result, "Initializing Kerberos failed");
        result = 1;
        goto cleanup;
    }

    // Parse principal names.
    result = krb5_parse_name(context, argv[1], &agent_principal);
    if (result != 0)
    {
        com_err(NAME, result, "Parsing agent principal name failed");
        result = 1;
        goto cleanup;
    }

    result = krb5_parse_name(context, argv[2], &target_principal);
    if (result != 0)
    {
        com_err(NAME, result, "Parsing target principal name failed");
        result = 1;
        goto cleanup;
    }

    fprintf(stderr, "Resetting password for %s\n", argv[2]);

    result = reset_password(
        context,
        agent_principal,
        getenv("KSETPWD_AGENT_PASSWORD"),
        target_principal,
        getenv("KSETPWD_TARGET_PASSWORD"));

cleanup:
    if (target_principal != NULL)
    {
        krb5_free_principal(context, target_principal);
    }

    if (agent_principal != NULL)
    {
        krb5_free_principal(context, agent_principal);
    }

    if (context != NULL)
    {
        krb5_free_context(context);
    }

    exit(result);
}
