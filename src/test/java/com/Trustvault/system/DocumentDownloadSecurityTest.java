package com.Trustvault.system;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.security.Principal;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;

import com.Trustvault.system.document.Document;
import com.Trustvault.system.document.DocumentStorageService;
import com.Trustvault.system.document.controller.DocumentController;
import com.Trustvault.system.document.repository.DocumentPermissionRepository;
import com.Trustvault.system.document.repository.DocumentRepository;
import com.Trustvault.system.repository.Useraccountrepository;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DocumentDownloadSecurityTest {

    private DocumentStorageService storageService;
    private DocumentRepository documentRepository;
    private Useraccountrepository userRepository;
    private DocumentPermissionRepository permissionRepository;
    private DocumentController controller;

    @BeforeEach
    void setUp() {
        storageService = mock(DocumentStorageService.class);
        documentRepository = mock(DocumentRepository.class);
        userRepository = mock(Useraccountrepository.class);
        permissionRepository = mock(DocumentPermissionRepository.class);

        controller = new DocumentController(
                storageService,
                documentRepository,
                userRepository,
                permissionRepository
        );
    }

    private Principal createPrincipal(String username) {
        Principal principal = mock(Principal.class);
        when(principal.getName()).thenReturn(username);
        return principal;
    }

    @Test
    void download_documentNotFound_throws404() {
        Principal principal = createPrincipal("adminUser");

        Useraccount admin = new Useraccount();
        admin.setUsername("adminUser");
        admin.setRole("ADMIN");
        when(userRepository.findByUsername("adminUser")).thenReturn(Optional.of(admin));
        when(documentRepository.findById(99L)).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
                controller.downloadDocument(99L, principal));

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
    }

    @Test
    void download_unauthorizedViewer_throwsAccessDeniedException() {
        Principal principal = createPrincipal("unauthorizedViewer");

        Useraccount viewer = new Useraccount();
        viewer.setUsername("unauthorizedViewer");
        viewer.setRole("VIEWER");

        Useraccount owner = new Useraccount();
        owner.setUsername("docOwner");
        owner.setRole("OWNER");

        Document doc = new Document();
        doc.setOwner(owner);

        when(userRepository.findByUsername("unauthorizedViewer")).thenReturn(Optional.of(viewer));
        when(documentRepository.findById(1L)).thenReturn(Optional.of(doc));
        when(permissionRepository.existsByDocumentIdAndViewerUsername(1L, "unauthorizedViewer")).thenReturn(false);

        assertThrows(AccessDeniedException.class, () ->
                controller.downloadDocument(1L, principal));
    }

    @Test
    void download_authorizedViewer_succeeds() throws Exception {
        Principal principal = createPrincipal("validViewer");

        Useraccount viewer = new Useraccount();
        viewer.setUsername("validViewer");
        viewer.setRole("VIEWER");

        Useraccount owner = new Useraccount();
        owner.setUsername("docOwner");
        owner.setRole("OWNER");

        Document doc = new Document();
        doc.setFileName("contract.pdf");
        doc.setOwner(owner);
        doc.setStoragePath("trustvault-files/sample-uuid");

        Resource mockResource = new InputStreamResource(new ByteArrayInputStream("data".getBytes()));

        when(userRepository.findByUsername("validViewer")).thenReturn(Optional.of(viewer));
        when(documentRepository.findById(1L)).thenReturn(Optional.of(doc));
        when(permissionRepository.existsByDocumentIdAndViewerUsername(1L, "validViewer")).thenReturn(true);
        when(storageService.loadAsResource("trustvault-files/sample-uuid")).thenReturn(mockResource);

        ResponseEntity<Resource> response = controller.downloadDocument(1L, principal);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getHeaders().getFirst("Content-Disposition").contains("contract.pdf"));
    }

    @Test
    void download_owner_succeeds() throws Exception {
        Principal principal = createPrincipal("docOwner");

        Useraccount owner = new Useraccount();
        owner.setUsername("docOwner");
        owner.setRole("OWNER");

        Document doc = new Document();
        doc.setFileName("owner_sheet.xlsx");
        doc.setOwner(owner);
        doc.setStoragePath("trustvault-files/sample-owner-uuid");

        Resource mockResource = new InputStreamResource(new ByteArrayInputStream("spreadsheet".getBytes()));

        when(userRepository.findByUsername("docOwner")).thenReturn(Optional.of(owner));
        when(documentRepository.findById(2L)).thenReturn(Optional.of(doc));
        when(storageService.loadAsResource("trustvault-files/sample-owner-uuid")).thenReturn(mockResource);

        ResponseEntity<Resource> response = controller.downloadDocument(2L, principal);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getHeaders().getFirst("Content-Disposition").contains("owner_sheet.xlsx"));
    }

    @Test
    void download_admin_succeedsForAnyDocument() throws Exception {
        Principal principal = createPrincipal("systemAdmin");

        Useraccount admin = new Useraccount();
        admin.setUsername("systemAdmin");
        admin.setRole("ADMIN");

        Useraccount owner = new Useraccount();
        owner.setUsername("someOwner");
        owner.setRole("OWNER");

        Document doc = new Document();
        doc.setFileName("any_doc.pdf");
        doc.setOwner(owner);
        doc.setStoragePath("trustvault-files/sample-any-uuid");

        Resource mockResource = new InputStreamResource(new ByteArrayInputStream("pdfcontent".getBytes()));

        when(userRepository.findByUsername("systemAdmin")).thenReturn(Optional.of(admin));
        when(documentRepository.findById(3L)).thenReturn(Optional.of(doc));
        when(storageService.loadAsResource("trustvault-files/sample-any-uuid")).thenReturn(mockResource);

        ResponseEntity<Resource> response = controller.downloadDocument(3L, principal);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    void download_missingFileOnDisk_throws404() throws Exception {
        Principal principal = createPrincipal("systemAdmin");

        Useraccount admin = new Useraccount();
        admin.setUsername("systemAdmin");
        admin.setRole("ADMIN");

        Useraccount owner = new Useraccount();
        owner.setUsername("someOwner");

        Document doc = new Document();
        doc.setFileName("deleted.pdf");
        doc.setOwner(owner);
        doc.setStoragePath("trustvault-files/deleted-uuid");

        when(userRepository.findByUsername("systemAdmin")).thenReturn(Optional.of(admin));
        when(documentRepository.findById(4L)).thenReturn(Optional.of(doc));
        when(storageService.loadAsResource("trustvault-files/deleted-uuid"))
                .thenThrow(new FileNotFoundException("File missing on disk"));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () ->
                controller.downloadDocument(4L, principal));

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
        assertEquals("Document file not found on server.", ex.getReason());
    }
}
