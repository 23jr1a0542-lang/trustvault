
package com.Trustvault.system.document;

import java.time.LocalDateTime;

import com.Trustvault.system.Useraccount;

import jakarta.persistence.*;

@Entity
@Table(name = "tv_documents")
public class Document {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String fileName;

    @Column(nullable = false, length = 100)
    private String category;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private Useraccount owner;

    @Column(nullable = false, length = 500)
    private String storagePath;

    @Column(nullable = false)
    private LocalDateTime uploadedAt;

    public Document() {
    }

    @PrePersist
    public void beforeInsert() {
        if (uploadedAt == null) {
            uploadedAt = LocalDateTime.now();
        }
    }

    public Long getId() {
        return id;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public Useraccount getOwner() {
        return owner;
    }

    public void setOwner(Useraccount owner) {
        this.owner = owner;
    }

    public String getStoragePath() {
        return storagePath;
    }

    public void setStoragePath(String storagePath) {
        this.storagePath = storagePath;
    }

    public LocalDateTime getUploadedAt() {
        return uploadedAt;
    }
}
