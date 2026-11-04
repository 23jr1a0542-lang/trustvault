package com.Trustvault.system.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.Trustvault.system.service.AuditLogService;

/*
 * Records login outcomes through the existing AuditLogService.
 * Only the account name is stored. Passwords, credentials, session ids
 * and tokens are never read here.
 *
 * A failure to write the audit record is logged as an error but must not
 * lock every user out of the application.
 */
@Component
public class AuthenticationAuditListener {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AuthenticationAuditListener.class);

    private final AuditLogService auditLogService;

    public AuthenticationAuditListener(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @EventListener
    public void onLoginSuccess(AuthenticationSuccessEvent event) {
        Authentication authentication = event.getAuthentication();

        try {
            auditLogService.log(
                    authentication.getName(),
                    "LOGIN",
                    null,
                    "User logged in",
                    "SUCCESS");
        } catch (RuntimeException ex) {
            LOGGER.error("Could not record login audit event", ex);
        }
    }

    @EventListener
    public void onLoginFailure(AbstractAuthenticationFailureEvent event) {
        Authentication authentication = event.getAuthentication();

        String reason = event instanceof AuthenticationFailureDisabledEvent
                ? "Login failed: account disabled"
                : "Login failed: invalid username or password";

        String attempted = authentication == null
                || authentication.getName() == null
                || authentication.getName().isBlank()
                        ? "(not provided)"
                        : authentication.getName();

        try {
            auditLogService.log(
                    attempted,
                    "LOGIN",
                    null,
                    reason,
                    "FAILURE");
        } catch (RuntimeException ex) {
            LOGGER.error("Could not record failed-login audit event", ex);
        }
    }
}
