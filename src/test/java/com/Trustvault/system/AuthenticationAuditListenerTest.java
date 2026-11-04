package com.Trustvault.system;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.authority.AuthorityUtils;

import com.Trustvault.system.security.AuditLogoutHandler;
import com.Trustvault.system.security.AuthenticationAuditListener;
import com.Trustvault.system.service.AuditLogService;

class AuthenticationAuditListenerTest {

    private AuditLogService auditLogService;
    private AuthenticationAuditListener listener;
    private AuditLogoutHandler logoutHandler;

    @BeforeEach
    void setUp() {
        auditLogService = mock(AuditLogService.class);
        listener = new AuthenticationAuditListener(auditLogService);
        logoutHandler = new AuditLogoutHandler(auditLogService);
    }

    @Test
    void successfulLogin_isRecordedOnce() {
        var auth = UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, AuthorityUtils.createAuthorityList("ROLE_OWNER"));

        listener.onLoginSuccess(new AuthenticationSuccessEvent(auth));

        verify(auditLogService).log(
                eq("alice"), eq("LOGIN"), isNull(), anyString(), eq("SUCCESS"));
    }

    @Test
    void failedLogin_recordsAttemptedUsernameButNeverThePassword() {
        var attempt = UsernamePasswordAuthenticationToken
                .unauthenticated("mallory", "S3cret-Pass-Word");

        listener.onLoginFailure(new AuthenticationFailureBadCredentialsEvent(
                attempt, new BadCredentialsException("bad")));

        verify(auditLogService).log(
                eq("mallory"), eq("LOGIN"), isNull(),
                argThat(d -> d != null && !d.contains("S3cret")),
                eq("FAILURE"));
    }

    @Test
    void disabledAccount_isRecordedAsFailureWithReason() {
        var attempt = UsernamePasswordAuthenticationToken
                .unauthenticated("bob", "pw");

        listener.onLoginFailure(new AuthenticationFailureDisabledEvent(
                attempt, new DisabledException("disabled")));

        verify(auditLogService).log(
                eq("bob"), eq("LOGIN"), isNull(),
                argThat(d -> d.contains("disabled")), eq("FAILURE"));
    }

    @Test
    void auditFailure_doesNotBreakLogin() {
        doThrow(new IllegalStateException("db down"))
                .when(auditLogService).log(
                        anyString(), anyString(), isNull(),
                        anyString(), anyString());

        var auth = UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, AuthorityUtils.createAuthorityList("ROLE_OWNER"));

        assertDoesNotThrow(
                () -> listener.onLoginSuccess(new AuthenticationSuccessEvent(auth)));
    }

    @Test
    void logout_isRecordedForAuthenticatedUser() {
        var auth = UsernamePasswordAuthenticationToken.authenticated(
                "alice", null, AuthorityUtils.createAuthorityList("ROLE_OWNER"));

        logoutHandler.logout(null, null, auth);

        verify(auditLogService).log(
                eq("alice"), eq("LOGOUT"), isNull(), anyString(), eq("SUCCESS"));
    }

    @Test
    void logout_withoutAuthenticatedUser_recordsNothing() {
        logoutHandler.logout(null, null, null);
        logoutHandler.logout(null, null, new AnonymousAuthenticationToken(
                "key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        verify(auditLogService, never()).log(any(), any(), any(), any(), any());
    }
}
