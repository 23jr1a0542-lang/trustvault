
package com.Trustvault.system.document.controller;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.document.Document;
import com.Trustvault.system.document.DocumentStorageService;
import com.Trustvault.system.document.repository.DocumentRepository;
import com.Trustvault.system.repository.Useraccountrepository;

@Controller
public class DocumentController {

    private final DocumentStorageService storageService;
    private final DocumentRepository documentRepository;
    private final Useraccountrepository userRepository;

    public DocumentController(
            DocumentStorageService storageService,
            DocumentRepository documentRepository,
            Useraccountrepository userRepository) {
        this.storageService = storageService;
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/documents")
    @ResponseBody
    public String documentsPage() {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>TrustVault Documents</title>
                </head>
                <body>
                    <h1>TrustVault Documents</h1>
                    <h2>Upload a document</h2>

                    <form id="uploadForm"
                          action="/documents/upload"
                          method="post"
                          enctype="multipart/form-data">

                        <label>Select a file:</label>
                        <input type="file" name="file" required>
                        <br><br>

                        <label>Category:</label>
                        <input type="text" name="category"
                               placeholder="e.g. Certificates" required>
                        <br><br>

                        <button type="submit">Upload</button>
                    </form>

                    <script>
                        document.getElementById("uploadForm")
                            .addEventListener("submit", function(event) {
                                const csrfToken = document.cookie
                                    .split("; ")
                                    .find(row => row.startsWith("XSRF-TOKEN="));

                                if (!csrfToken) {
                                    event.preventDefault();
                                    alert("CSRF token not found. Refresh the page and try again.");
                                    return;
                                }

                                const token = decodeURIComponent(
                                    csrfToken.substring("XSRF-TOKEN=".length)
                                );

                                let csrfInput = document.createElement("input");
                                csrfInput.type = "hidden";
                                csrfInput.name = "_csrf";
                                csrfInput.value = token;
                                this.appendChild(csrfInput);
                            });
                    </script>
                </body>
                </html>
                """;
    }

    @PostMapping("/documents/upload")
    @ResponseBody
    public String uploadDocument(
            @RequestParam("file") MultipartFile file,
            @RequestParam("category") String category,
            Principal principal) throws Exception {

        Useraccount owner = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                    new IllegalStateException("Logged-in user not found"));

        String storagePath = storageService.store(file);

        Document document = new Document();
        document.setFileName(file.getOriginalFilename());
        document.setCategory(category.trim());
        document.setOwner(owner);
        document.setStoragePath(storagePath);

        documentRepository.save(document);

        return """
                <h2>Document uploaded successfully!</h2>
                <p>Your document details have been saved.</p>
                <a href="/documents">Upload another document</a>
                """;
    }
}
