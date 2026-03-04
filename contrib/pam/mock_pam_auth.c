/*
 * mock_pam_auth.c — Mock PAM auth module for testing pam_rosec.
 *
 * This module simulates pam_unix: it prompts for a password via the
 * PAM conversation function and stores it as PAM_AUTHTOK.  This is
 * what pam_rosec expects to find when it runs in the auth phase.
 *
 * Build:
 *   cc -shared -fPIC -O2 -Wall -o pam_mock_auth.so mock_pam_auth.c -lpam
 */

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    const struct pam_conv *conv;
    struct pam_message msg;
    struct pam_response *resp = NULL;
    const struct pam_message *msgs[1];
    int ret;

    (void)flags;
    (void)argc;
    (void)argv;

    ret = pam_get_item(ph, PAM_CONV, (const void **)&conv);
    if (ret != PAM_SUCCESS || !conv)
        return PAM_AUTH_ERR;

    memset(&msg, 0, sizeof(msg));
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = "Password: ";
    msgs[0] = &msg;

    ret = conv->conv(1, msgs, &resp, conv->appdata_ptr);
    if (ret != PAM_SUCCESS || !resp || !resp[0].resp) {
        free(resp);
        return PAM_AUTH_ERR;
    }

    ret = pam_set_item(ph, PAM_AUTHTOK, resp[0].resp);

    /* Zeroize and free the response */
    if (resp[0].resp) {
        memset(resp[0].resp, 0, strlen(resp[0].resp));
        free(resp[0].resp);
    }
    free(resp);

    return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    (void)ph; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    (void)ph; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *ph, int flags, int argc, const char **argv)
{
    (void)ph; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
