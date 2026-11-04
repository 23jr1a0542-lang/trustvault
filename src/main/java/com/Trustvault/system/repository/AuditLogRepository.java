
package com.Trustvault.system.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.Trustvault.system.AuditLog;

public interface AuditLogRepository
        extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findAllByOrderByTimestampDesc();

    // Newest first; id breaks ties when two events share a timestamp.
    List<AuditLog> findAllByOrderByTimestampDescIdDesc();

    List<AuditLog> findTop10ByOrderByTimestampDescIdDesc();
}
