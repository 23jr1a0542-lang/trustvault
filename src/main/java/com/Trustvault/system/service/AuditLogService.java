
package com.Trustvault.system.service;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.Trustvault.system.AuditLog;
import com.Trustvault.system.repository.AuditLogRepository;

@Service
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(
            String username,
            String action,
            String details,
            String result) {

        AuditLog auditLog = new AuditLog();

        auditLog.setUsername(
                username == null || username.isBlank()
                        ? "SYSTEM"
                        : limit(username, 100));

        auditLog.setAction(limit(action, 100));
        auditLog.setDetails(limit(details, 255));
        auditLog.setResult(limit(result, 30));
        auditLog.setTimestamp(LocalDateTime.now());

        System.out.println("AUDIT LOG CALLED: " + action);

        auditLogRepository.save(auditLog);

        System.out.println("AUDIT LOG SAVE REQUEST COMPLETED");
    }

    private String limit(String value, int maxLength) {
        if (value == null || value.isBlank()) {
            return "Not specified";
        }

        String cleaned = value.trim();

        return cleaned.length() > maxLength
                ? cleaned.substring(0, maxLength)
                : cleaned;
    }
}
