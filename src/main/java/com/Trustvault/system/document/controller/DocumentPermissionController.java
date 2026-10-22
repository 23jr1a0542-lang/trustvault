
package com.Trustvault.system.document.controller;

import java.security.Principal;
import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.document.Document;
import com.Trustvault.system.document.Documentpermission;
import com.Trustvault.system.document.repository.DocumentRepository;
import com.Trustvault.system.document.repository.DocumentPermissionRepository;
import com.Trustvault.system.repository.Useraccountrepository;

@Controller
public class DocumentPermissionController {

    private final DocumentRepository documentRepository;
    private final DocumentPermissionRepository permissionRepository;
    private final Useraccountrepository userRepository;

    public DocumentPermissionController(
            DocumentRepository documentRepository,
            DocumentPermissionRepository permissionRepository,
            Useraccountrepository userRepository) {
        this.documentRepository = documentRepository;
        this.permissionRepository = permissionRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/documents/share")
    @ResponseBody
    public String sharePage(Principal principal, CsrfToken csrfToken) {

        Useraccount currentUser = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                        new IllegalStateException("User not found"));

        boolean isAdmin = "ADMIN".equals(currentUser.getRole());
        boolean isOwner = "OWNER".equals(currentUser.getRole());

        if (!isAdmin && !isOwner) {
            throw new AccessDeniedException(
                    "Only Admins and Owners can share documents.");
        }

        List<Document> documents;

        if (isAdmin) {
            documents = documentRepository.findAll();
        } else {
            documents = documentRepository
                    .findByOwnerUsername(currentUser.getUsername());
        }

        StringBuilder options = new StringBuilder();

        for (Document document : documents) {
            options.append("<option value=\"")
                    .append(document.getId())
                    .append("\">")
                    .append(escapeHtml(document.getFileName()))
                    .append("</option>");
        }

        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Share Document - TrustVault</title>
                </head>
                <body>
                    <h2>Share a Document</h2>
                    <form method="post" action="/documents/share">
                        <input type="hidden" name="_csrf" value="%s">

                        <label>Select document:</label>
                        <select name="documentId" required>
                            %s
                        </select>
                        <br><br>

                        <label>Viewer username:</label>
                        <input type="text" name="viewerUsername" required>
                        <br><br>

                        <button type="submit">Share Document</button>
                    </form>

                    <p><a href="/documents">Back to Documents</a></p>
                </body>
                </html>
                """.formatted(
                    escapeHtml(csrfToken.getToken()),
                    options.toString());
    }

    @PostMapping("/documents/share")
    @ResponseBody
    public String shareDocument(
            @RequestParam Long documentId,
            @RequestParam String viewerUsername,
            Principal principal) {

        Useraccount currentUser = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                        new IllegalStateException("User not found"));

        boolean isAdmin = "ADMIN".equals(currentUser.getRole());
        boolean isOwner = "OWNER".equals(currentUser.getRole());

        if (!isAdmin && !isOwner) {
            throw new AccessDeniedException(
                    "Only Admins and Owners can share documents.");
        }

        Document document = documentRepository.findById(documentId)
                .orElseThrow(() ->
                        new IllegalArgumentException("Document not found."));

        if (isOwner && (document.getOwner() == null
                || !document.getOwner().getUsername()
                        .equals(currentUser.getUsername()))) {
            throw new AccessDeniedException(
                    "You can only share your own documents.");
        }

        String username = viewerUsername.trim();

        Useraccount viewer = userRepository
                .findByUsername(username)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Viewer username not found."));

        if (!"VIEWER".equals(viewer.getRole())) {
            throw new IllegalArgumentException(
                    "The selected user must have the VIEWER role.");
        }

        if (permissionRepository
                .existsByDocumentIdAndViewerUsername(
                        documentId, viewer.getUsername())) {
            return """
                    <!DOCTYPE html>
                    <html>
                    <head><meta charset="UTF-8">
                    <title>TrustVault</title></head>
                    <body>
                        <h3>This document is already shared with this Viewer.</h3>
                        <a href="/documents/share">Go back</a>
                    </body>
                    </html>
                    """;
        }

        Documentpermission permission = new Documentpermission();
        permission.setDocument(document);
        permission.setViewer(viewer);

        permissionRepository.save(permission);

        return """
                <!DOCTYPE html>
                <html>
                <head><meta charset="UTF-8">
                <title>TrustVault</title></head>
                <body>
                    <h3>Document shared successfully!</h3>
                    <p>The Viewer can now see the document in their list.</p>
                    <a href="/documents/share">Share another document</a>
                    <br><br>
                    <a href="/documents">Back to Documents</a>
                </body>
                </html>
                """;
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }

        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
