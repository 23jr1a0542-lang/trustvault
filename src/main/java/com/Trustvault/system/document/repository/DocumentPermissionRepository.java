
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

    // Find all document permissions assigned to a viewer.
    List<Documentpermission> findByViewerUsername(String username);

    // Check whether a viewer has permission to access a document.
    boolean existsByDocumentIdAndViewerUsername(
            Long documentId,
            String username
    );

    // Find the viewer's permissions together with document details.
    @Query("SELECT p FROM Documentpermission p "
            + "JOIN FETCH p.document "
            + "WHERE p.viewer.username = :username")
    List<Documentpermission> findByViewerUsernameWithDocument(
            @Param("username") String username
    );

    // Remove all sharing permissions for a particular document.
    @Modifying
    @Transactional
    @Query("DELETE FROM Documentpermission p "
            + "WHERE p.document.id = :documentId")
    void deleteByDocumentId(
            @Param("documentId") Long documentId
    );

    // Revoke all document-sharing permissions assigned to a user.
    @Modifying
    @Transactional
    @Query("DELETE FROM Documentpermission p "
            + "WHERE p.viewer.username = :username")
    void deleteByViewerUsername(
            @Param("username") String username
    );
}
