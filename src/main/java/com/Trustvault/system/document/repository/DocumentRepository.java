
package com.Trustvault.system.document.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.Trustvault.system.document.Document;

public interface DocumentRepository
        extends JpaRepository<Document, Long> {

    List<Document> findByFileNameContainingIgnoreCase(String fileName);

    List<Document> findByCategoryIgnoreCase(String category);

    List<Document> findByOwnerUsername(String username);
}
