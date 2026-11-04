package com.Trustvault.system;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Principal;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.web.csrf.CsrfToken;

import com.Trustvault.system.document.Document;
import com.Trustvault.system.document.DocumentStorageService;
import com.Trustvault.system.document.controller.DocumentController;
import com.Trustvault.system.document.repository.DocumentPermissionRepository;
import com.Trustvault.system.document.repository.DocumentRepository;
import com.Trustvault.system.repository.Useraccountrepository;
import com.Trustvault.system.service.AuditLogService;

/**
 * Unit tests: the upload endpoint must write exactly one audit record
 * per upload attempt outcome, through the existing AuditLogService.
 */
class DocumentUploadAuditTest {

    private DocumentStorageService storageService;
    private DocumentRepository documentRepository;
    private Useraccountrepository userRepository;
    private AuditLogService auditLogService;
    private DocumentController controller;
    private Principal principal;
    private CsrfToken csrfToken;

    @BeforeEach
    void setUp() {
        storageService = mock(DocumentStorageService.class);
        documentRepository = mock(DocumentRepository.class);
        userRepository = mock(Useraccountrepository.class);
        auditLogService = mock(AuditLogService.class);

        controller = new DocumentController(
                storageService,
                documentRepository,
                userRepository,
                mock(DocumentPermissionRepository.class),
                auditLogService);

        principal = mock(Principal.class);
        when(principal.getName()).thenReturn("owner1");

        csrfToken = mock(CsrfToken.class);
        when(csrfToken.getToken()).thenReturn("token");

        Useraccount owner = new Useraccount();
        owner.setUsername("owner1");
        owner.setRole("OWNER");
        when(userRepository.findByUsername("owner1"))
                .thenReturn(Optional.of(owner));
    }

    private static void setId(Document document, long id) throws Exception {
        Field field = Document.class.getDeclaredField("id");
        field.setAccessible(true);
        field.set(document, id);
    }

    @Test
    void successfulUpload_writesSuccessAuditRecord() throws Exception {
        when(storageService.store(any())).thenReturn("stored-uuid");
        when(documentRepository.existsByFileNameIgnoreCaseAndOwnerUsername(
                anyString(), anyString())).thenReturn(false);
        when(documentRepository.save(any(Document.class)))
                .thenAnswer(invocation -> {
                    Document d = invocation.getArgument(0);
                    setId(d, 42L);
                    return d;
                });

        MockMultipartFile file = new MockMultipartFile(
                "file", "report.pdf", "application/pdf", "data".getBytes());

        String page = controller.uploadDocument(
                file, "PDF", false, principal, csrfToken);

        assertTrue(page.contains("Document uploaded successfully"));
        verify(auditLogService).log(
                eq("owner1"),
                eq("DOCUMENT_UPLOAD"),
                contains("report.pdf"),
                anyString(),
                eq("SUCCESS"));
    }

    @Test
    void failedUpload_writesFailureAuditRecordAndRethrows() throws Exception {
        when(storageService.store(any()))
                .thenThrow(new IOException("disk full"));

        MockMultipartFile file = new MockMultipartFile(
                "file", "report.pdf", "application/pdf", "data".getBytes());

        assertThrows(IOException.class, () -> controller.uploadDocument(
                file, "PDF", false, principal, csrfToken));

        verify(auditLogService).log(
                eq("owner1"),
                eq("DOCUMENT_UPLOAD"),
                contains("report.pdf"),
                anyString(),
                eq("FAILURE"));
        verify(documentRepository, never()).save(any());
    }

    @Test
    void emptyFile_isRejectedWithoutAuditRecord() throws Exception {
        MockMultipartFile empty = new MockMultipartFile(
                "file", "empty.txt", "text/plain", new byte[0]);

        String page = controller.uploadDocument(
                empty, "TXT", false, principal, csrfToken);

        assertTrue(page.contains("No file selected"));
        verify(auditLogService, never()).log(any(), any(), any(), any(), any());
        verify(auditLogService, never()).log(
                anyString(), anyString(), anyString(), anyString());
    }
}
