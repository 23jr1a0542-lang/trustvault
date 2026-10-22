package com.Trustvault.system.document.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import com.Trustvault.system.document.Documentpermission;

public interface DocumentPermissionRepository
        extends JpaRepository<Documentpermission, Long> {

    List<Documentpermission> findByViewerUsername(String username);

    boolean existsByDocumentIdAndViewerUsername(
            Long documentId, String username);

    @Query("SELECT p FROM Documentpermission p " +
           "JOIN FETCH p.document " +
           "WHERE p.viewer.username = :username")
    List<Documentpermission> findByViewerUsernameWithDocument(
            @Param("username") String username);

    @Modifying
    @Transactional
    @Query("DELETE FROM Documentpermission p WHERE p.document.id = :documentId")
    void deleteByDocumentId(@Param("documentId") Long documentId);
}
