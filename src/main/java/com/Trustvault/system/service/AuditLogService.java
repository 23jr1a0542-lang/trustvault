
package com.Trustvault.system.service;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.Trustvault.system.AuditLog;
import com.Trustvault.system.Useraccount;
import com.Trustvault.system.document.Document;
import com.Trustvault.system.repository.AuditLogRepository;
import com.Trustvault.system.repository.Useraccountrepository;

@Service
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;
    private final Useraccountrepository userRepository;

    public AuditLogService(
            AuditLogRepository auditLogRepository,
            Useraccountrepository userRepository) {
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
    }

    /*
     * Existing signature, kept so current callers keep working.
     * The actor's role is looked up from the account table.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(
            String username,
            String action,
            String details,
            String result) {

        record(username, action, null, details, result);
    }

    /*
     * Full signature. "target" is the document or account the action
     * was about. Runs in its own transaction so the record is committed
     * even when the calling request later fails or is denied.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(
            String username,
            String action,
            String target,
            String details,
            String result) {

        record(username, action, target, details, result);
    }

    /* Short, secret-free description of a document for audit entries. */
    public static String describe(Document document) {
        if (document == null) {
            return null;
        }

        return document.getFileName() + " (id=" + document.getId() + ")";
    }

    private void record(
            String username,
            String action,
            String target,
            String details,
            String result) {

        String actor = username == null || username.isBlank()
                ? "SYSTEM"
                : limit(username, 100);

        AuditLog auditLog = new AuditLog();
        auditLog.setUsername(actor);
        auditLog.setActorRole(findRole(actor));
        auditLog.setAction(limit(action, 100));
        auditLog.setTarget(target == null || target.isBlank()
                ? null
                : limit(target, 255));
        auditLog.setDetails(limit(details, 255));
        auditLog.setResult(limit(result, 30));
        auditLog.setTimestamp(LocalDateTime.now());

        auditLogRepository.save(auditLog);
    }

    private String findRole(String username) {
        return userRepository.findByUsername(username)
                .map(Useraccount::getRole)
                .orElse(null);
    }

    /*
     * Trims, removes control characters (prevents forged multi-line
     * entries) and enforces the column length.
     */
    private String limit(String value, int maxLength) {
        if (value == null || value.isBlank()) {
            return "Not specified";
        }

        String cleaned = value.replaceAll("\\p{Cntrl}", " ").trim();

        if (cleaned.isEmpty()) {
            return "Not specified";
        }

        return cleaned.length() > maxLength
                ? cleaned.substring(0, maxLength)
                : cleaned;
    }
}
