
package com.Trustvault.system.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.Trustvault.system.AuditLog;

public interface AuditLogRepository
        extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findAllByOrderByTimestampDesc();
}
