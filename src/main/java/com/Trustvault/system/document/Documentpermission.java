
package com.Trustvault.system.document;

import com.Trustvault.system.Useraccount;

import jakarta.persistence.*;

@Entity
@Table(
    name = "tv_document_permissions",
    uniqueConstraints = @UniqueConstraint(
        columnNames = {"document_id", "viewer_id"}
    )
)
public class Documentpermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "document_id", nullable = false)
    private Document document;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "viewer_id", nullable = false)
    private Useraccount viewer;

    public Documentpermission() {
    }

    public Long getId() {
        return id;
    }

    public Document getDocument() {
        return document;
    }

    public void setDocument(Document document) {
        this.document = document;
    }

    public Useraccount getViewer() {
        return viewer;
    }

    public void setViewer(Useraccount viewer) {
        this.viewer = viewer;
    }
}
