package com.Trustvault.system.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import com.Trustvault.system.service.AuditLogService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/*
 * Records an explicit logout. If the session had already expired there is
 * no authenticated user, so nothing is recorded (no guessed events).
 */
@Component
public class AuditLogoutHandler implements LogoutHandler {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AuditLogoutHandler.class);

    private final AuditLogService auditLogService;

    public AuditLogoutHandler(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {

        if (authentication == null
                || authentication instanceof AnonymousAuthenticationToken
                || authentication.getName() == null
                || authentication.getName().isBlank()) {
            return;
        }

        try {
            auditLogService.log(
                    authentication.getName(),
                    "LOGOUT",
                    null,
                    "User logged out",
                    "SUCCESS");
        } catch (RuntimeException ex) {
            LOGGER.error("Could not record logout audit event", ex);
        }
    }
}
