package com.Trustvault.system;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.Trustvault.system.document.Document;
import com.Trustvault.system.document.repository.DocumentRepository;
import com.Trustvault.system.repository.AuditLogRepository;
import com.Trustvault.system.repository.Useraccountrepository;

/**
 * End-to-end checks against the real Spring context and the H2 (MySQL
 * mode) test database. Each "user" works in a separate session, and
 * sessions are discarded between steps to mimic closing a tab.
 */
@SpringBootTest
class AdminDashboardAuditIntegrationTest {

    private static final String PASSWORD = "UserPassw0rd!";
    private static final String ADMIN_PASSWORD = "testAdminPassword123";

    @Autowired private WebApplicationContext context;
    @Autowired private Useraccountrepository userRepository;
    @Autowired private DocumentRepository documentRepository;
    @Autowired private AuditLogRepository auditLogRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private MockMvc mvc;
    private String owner;
    private String otherOwner;
    private String viewer;
    private String outsider;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();

        String suffix = UUID.randomUUID().toString().substring(0, 8);
        owner = createUser("owner_" + suffix, "OWNER");
        otherOwner = createUser("owner2_" + suffix, "OWNER");
        viewer = createUser("viewer_" + suffix, "VIEWER");
        outsider = createUser("outsider_" + suffix, "VIEWER");
    }

    private String createUser(String name, String role) {
        Useraccount user = new Useraccount();
        user.setUsername(name);
        user.setPasswordHash(passwordEncoder.encode(PASSWORD));
        user.setRole(role);
        user.setEnabled(true);
        userRepository.save(user);
        return name;
    }

    // ---------------------------------------------------------- helpers

    private MockHttpSession login(String user, String password)
            throws Exception {
        MvcResult result = mvc.perform(
                formLogin().user(user).password(password)).andReturn();
        MockHttpSession session =
                (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(session, "login must create a session for " + user);
        return session;
    }

    private void logout(MockHttpSession session) throws Exception {
        mvc.perform(post("/logout").session(session).with(csrf()))
                .andReturn();
    }

    private void upload(MockHttpSession session, String fileName)
            throws Exception {
        MvcResult result = mvc.perform(multipart("/documents/upload")
                .file(new MockMultipartFile(
                        "file", fileName, "application/pdf",
                        ("content-of-" + fileName).getBytes()))
                .param("category", "PDF")
                .session(session)
                .with(csrf()))
                .andReturn();

        assertEquals(200, result.getResponse().getStatus());
        assertTrue(result.getResponse().getContentAsString()
                .contains("Document uploaded successfully"));
    }

    private long documentId(String ownerName, String fileName) {
        return documentRepository
                .findByOwnerUsernameOrderByIdDesc(ownerName).stream()
                .filter(d -> fileName.equals(d.getFileName()))
                .findFirst().orElseThrow().getId();
    }

    private int status(MockHttpSession session, String url) throws Exception {
        return mvc.perform(get(url).session(session))
                .andReturn().getResponse().getStatus();
    }

    private String body(MockHttpSession session, String url) throws Exception {
        MvcResult result = mvc.perform(get(url).session(session)).andReturn();
        assertEquals(200, result.getResponse().getStatus());
        return result.getResponse().getContentAsString();
    }

    private List<AuditLog> events(String user, String action) {
        return auditLogRepository.findAllByOrderByTimestampDescIdDesc()
                .stream()
                .filter(l -> user.equals(l.getUsername())
                        && action.equals(l.getAction()))
                .toList();
    }

    private static long stat(String html, String id) {
        Matcher m = Pattern.compile("id=\"" + id + "\">(\\d+)<").matcher(html);
        assertTrue(m.find(), "stat " + id + " missing from admin dashboard");
        return Long.parseLong(m.group(1));
    }

    // ------------------------------------------------------------ login

    @Test
    void successfulLogin_isRecordedForAdminOwnerAndViewer() throws Exception {
        login("admin", ADMIN_PASSWORD);
        login(owner, PASSWORD);
        login(viewer, PASSWORD);

        AuditLog adminLogin = events("admin", "LOGIN").get(0);
        assertEquals("ADMIN", adminLogin.getActorRole());
        assertEquals("SUCCESS", adminLogin.getResult());
        assertNotNull(adminLogin.getTimestamp());

        assertEquals(1, events(owner, "LOGIN").size());
        assertEquals("OWNER", events(owner, "LOGIN").get(0).getActorRole());
        assertEquals(1, events(viewer, "LOGIN").size());
        assertEquals("VIEWER", events(viewer, "LOGIN").get(0).getActorRole());
    }

    @Test
    void failedLogin_isRecordedWithoutThePassword() throws Exception {
        String wrongPassword = "Wrong-Pass-" + UUID.randomUUID();

        mvc.perform(formLogin().user(owner).password(wrongPassword))
                .andReturn();
        mvc.perform(formLogin().user("no_such_user_x").password(wrongPassword))
                .andReturn();

        AuditLog known = events(owner, "LOGIN").get(0);
        assertEquals("FAILURE", known.getResult());
        assertEquals("OWNER", known.getActorRole());

        AuditLog unknown = events("no_such_user_x", "LOGIN").get(0);
        assertEquals("FAILURE", unknown.getResult());
        assertEquals(null, unknown.getActorRole());

        for (AuditLog log : auditLogRepository.findAll()) {
            String all = String.join("|",
                    String.valueOf(log.getUsername()),
                    String.valueOf(log.getAction()),
                    String.valueOf(log.getTarget()),
                    String.valueOf(log.getDetails()),
                    String.valueOf(log.getResult()));
            assertFalse(all.contains(wrongPassword),
                    "audit entry must never contain a password");
            assertFalse(all.toLowerCase().contains("jsessionid"));
        }
    }

    @Test
    void logout_isRecorded() throws Exception {
        MockHttpSession session = login(owner, PASSWORD);
        logout(session);

        List<AuditLog> logouts = events(owner, "LOGOUT");
        assertEquals(1, logouts.size());
        assertEquals("SUCCESS", logouts.get(0).getResult());
    }

    // -------------------------------------------- owner/viewer workflow

    @Test
    void ownerUpload_viewerDownload_andDeniedAttempt_areAuditedAndVisibleToAdmin()
            throws Exception {
        String fileName = "contract-" + UUID.randomUUID() + ".pdf";

        // Admin dashboard opened BEFORE any activity (stale-data check).
        MockHttpSession adminSession = login("admin", ADMIN_PASSWORD);
        String before = body(adminSession, "/admin");
        long docsBefore = stat(before, "statDocuments");
        assertFalse(before.contains(fileName));

        // Owner uploads and shares, then the tab is closed (logout).
        MockHttpSession ownerSession = login(owner, PASSWORD);
        upload(ownerSession, fileName);
        long id = documentId(owner, fileName);

        mvc.perform(post("/api/documents/" + id + "/share")
                .param("viewerUsername", viewer)
                .session(ownerSession).with(csrf())).andReturn();
        logout(ownerSession);

        // Viewer downloads the shared document.
        MockHttpSession viewerSession = login(viewer, PASSWORD);
        assertEquals(200,
                status(viewerSession, "/documents/" + id + "/download"));
        logout(viewerSession);

        // A different viewer without permission is denied.
        MockHttpSession outsiderSession = login(outsider, PASSWORD);
        assertEquals(403,
                status(outsiderSession, "/documents/" + id + "/download"));

        // Persisted state and correct ownership.
        Document saved = documentRepository
                .findByOwnerUsernameOrderByIdDesc(owner).get(0);
        assertEquals(owner, saved.getOwner().getUsername());

        // Audit records: one each, correct actor/role/target/result.
        AuditLog upload = events(owner, "DOCUMENT_UPLOAD").get(0);
        assertEquals("SUCCESS", upload.getResult());
        assertEquals("OWNER", upload.getActorRole());
        assertTrue(upload.getTarget().contains(fileName));
        assertEquals(1, events(owner, "DOCUMENT_UPLOAD").size());

        AuditLog share = events(owner, "DOCUMENT_SHARE").get(0);
        assertEquals("SUCCESS", share.getResult());
        assertTrue(share.getDetails().contains(viewer));
        assertEquals(1, events(owner, "DOCUMENT_SHARE").size());

        List<AuditLog> viewerDownloads = events(viewer, "DOCUMENT_DOWNLOAD");
        assertEquals(1, viewerDownloads.size());
        assertEquals("SUCCESS", viewerDownloads.get(0).getResult());
        assertEquals("VIEWER", viewerDownloads.get(0).getActorRole());

        List<AuditLog> denied = events(outsider, "DOCUMENT_DOWNLOAD");
        assertEquals(1, denied.size());
        assertEquals("DENIED", denied.get(0).getResult());
        assertTrue(denied.get(0).getTarget().contains(fileName));

        // The SAME admin session sees everything on its next request.
        String after = body(adminSession, "/admin");
        assertEquals(docsBefore + 1, stat(after, "statDocuments"));
        assertTrue(after.contains(fileName));
        assertTrue(after.contains("DOCUMENT_UPLOAD"));

        // A brand-new admin login sees the full history.
        MockHttpSession freshAdmin = login("admin", ADMIN_PASSWORD);
        String history = body(freshAdmin, "/admin/audit-logs");
        for (String expected : List.of(owner, viewer, outsider,
                "DOCUMENT_UPLOAD", "DOCUMENT_SHARE", "DOCUMENT_DOWNLOAD",
                "DENIED", "LOGIN", "LOGOUT", fileName)) {
            assertTrue(history.contains(expected),
                    "audit history should contain " + expected);
        }

        // Newest-first ordering in the repository query (timestamp, id).
        List<AuditLog> ordered =
                auditLogRepository.findAllByOrderByTimestampDescIdDesc();
        for (int i = 1; i < ordered.size(); i++) {
            AuditLog newer = ordered.get(i - 1);
            AuditLog older = ordered.get(i);
            assertTrue(!newer.getTimestamp().isBefore(older.getTimestamp()),
                    "audit events must be newest first");
        }
    }

    // ---------------------------------------------------- visibility

    @Test
    void documentVisibility_followsRole() throws Exception {
        String mine = "mine-" + UUID.randomUUID() + ".pdf";
        String theirs = "theirs-" + UUID.randomUUID() + ".pdf";
        String shared = "shared-" + UUID.randomUUID() + ".pdf";

        MockHttpSession ownerSession = login(owner, PASSWORD);
        upload(ownerSession, mine);
        upload(ownerSession, shared);

        MockHttpSession otherSession = login(otherOwner, PASSWORD);
        upload(otherSession, theirs);

        mvc.perform(post("/api/documents/" + documentId(owner, shared)
                + "/share")
                .param("viewerUsername", viewer)
                .session(ownerSession).with(csrf())).andReturn();

        // Owner: only own documents.
        String ownerJson = body(ownerSession, "/api/documents");
        assertTrue(ownerJson.contains(mine));
        assertTrue(ownerJson.contains(shared));
        assertFalse(ownerJson.contains(theirs));

        // Viewer: only the authorized one.
        MockHttpSession viewerSession = login(viewer, PASSWORD);
        String viewerJson = body(viewerSession, "/api/documents");
        assertTrue(viewerJson.contains(shared));
        assertFalse(viewerJson.contains(mine));
        assertFalse(viewerJson.contains(theirs));

        // Admin: everything, read-only for other owners' files.
        MockHttpSession adminSession = login("admin", ADMIN_PASSWORD);
        String adminJson = body(adminSession, "/api/documents");
        assertTrue(adminJson.contains(mine));
        assertTrue(adminJson.contains(shared));
        assertTrue(adminJson.contains(theirs));
        assertTrue(adminJson.contains("\"canDownload\":false"));

        String adminPage = body(adminSession, "/documents");
        assertTrue(adminPage.contains(theirs));
        assertTrue(adminPage.contains(otherOwner));
    }

    // -------------------------------------------------------- access

    @Test
    void ownerAndViewer_cannotOpenAdminPages() throws Exception {
        MockHttpSession ownerSession = login(owner, PASSWORD);
        MockHttpSession viewerSession = login(viewer, PASSWORD);

        assertEquals(403, status(ownerSession, "/admin/audit-logs"));
        assertEquals(403, status(viewerSession, "/admin/audit-logs"));
        assertEquals(403, status(ownerSession, "/admin"));
        assertEquals(403, status(viewerSession, "/admin"));
    }

    @Test
    void recentActivity_isNewestFirst() throws Exception {
        String first = "first-" + UUID.randomUUID() + ".pdf";
        String second = "second-" + UUID.randomUUID() + ".pdf";

        MockHttpSession ownerSession = login(owner, PASSWORD);
        upload(ownerSession, first);
        upload(ownerSession, second);

        MockHttpSession adminSession = login("admin", ADMIN_PASSWORD);

        String dashboard = body(adminSession, "/admin");
        assertTrue(dashboard.indexOf(second) >= 0
                && dashboard.indexOf(first) >= 0);
        assertTrue(dashboard.indexOf(second) < dashboard.indexOf(first));

        String history = body(adminSession, "/admin/audit-logs");
        assertTrue(history.indexOf(second) < history.indexOf(first));
    }
}
