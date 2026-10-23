
package com.Trustvault.system.controller;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.document.repository.DocumentPermissionRepository;
import com.Trustvault.system.repository.Useraccountrepository;
import com.Trustvault.system.service.AuditLogService;

@Controller
@RequestMapping("/admin/users")
public class AdminUserController {

    private final Useraccountrepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final DocumentPermissionRepository permissionRepository;
    private final AuditLogService auditLogService;

    public AdminUserController(
            Useraccountrepository userRepository,
            PasswordEncoder passwordEncoder,
            DocumentPermissionRepository permissionRepository,
            AuditLogService auditLogService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.permissionRepository = permissionRepository;
        this.auditLogService = auditLogService;
    }

    private boolean isAdmin(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Useraccount user = userRepository
                .findByUsername(authentication.getName())
                .orElse(null);

        return user != null
                && "ADMIN".equalsIgnoreCase(user.getRole())
                && user.isEnabled();
    }

    @GetMapping
    @ResponseBody
    public String usersPage(
            Authentication authentication,
            CsrfToken csrf) {

        if (!isAdmin(authentication)) {
            return messagePage(
                    "Access denied",
                    "Only active administrators can manage users.");
        }

        String token = escapeHtml(csrf.getToken());
        List<Useraccount> users = userRepository.findAll();
        StringBuilder rows = new StringBuilder();

        for (Useraccount user : users) {
            String username = escapeHtml(user.getUsername());
            String role = escapeHtml(user.getRole());
            String status = user.isEnabled() ? "Active" : "Inactive";

            rows.append("<tr>");
            rows.append("<td>").append(username).append("</td>");
            rows.append("<td>").append(role).append("</td>");
            rows.append("<td>").append(status).append("</td>");
            rows.append("<td>");

            String action = user.isEnabled()
                    ? "/admin/users/deactivate"
                    : "/admin/users/activate";

            String buttonText = user.isEnabled()
                    ? "Deactivate"
                    : "Reactivate";

            String buttonClass = user.isEnabled()
                    ? "deactivate"
                    : "activate";

            rows.append("<form method=\"post\" action=\"")
                    .append(action)
                    .append("\" onsubmit=\"return confirm('Confirm this account action?');\">");

            rows.append("<input type=\"hidden\" name=\"_csrf\" value=\"")
                    .append(token)
                    .append("\">");

            rows.append("<input type=\"hidden\" name=\"username\" value=\"")
                    .append(username)
                    .append("\">");

            rows.append("<button class=\"")
                    .append(buttonClass)
                    .append("\" type=\"submit\">")
                    .append(buttonText)
                    .append("</button>");

            rows.append("</form>");
            rows.append("</td>");
            rows.append("</tr>");
        }

        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport"
                      content="width=device-width, initial-scale=1">
                <title>TrustVault - User Management</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background: #f3f5f9;
                        margin: 0;
                        padding: 25px;
                        color: #202b3c;
                    }
                    .container {
                        max-width: 1000px;
                        margin: 20px auto;
                        background: white;
                        padding: 28px;
                        border-radius: 12px;
                        box-shadow: 0 4px 18px #00000012;
                    }
                    h1, h2 {
                        color: #183b70;
                    }
                    label {
                        display: block;
                        margin-top: 15px;
                        font-weight: bold;
                    }
                    input, select {
                        box-sizing: border-box;
                        width: 100%;
                        padding: 11px;
                        margin-top: 7px;
                        border: 1px solid #ccd3df;
                        border-radius: 6px;
                    }
                    button {
                        padding: 10px 14px;
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        color: white;
                        margin: 4px 0;
                    }
                    .create {
                        background: #183b70;
                        margin-top: 20px;
                    }
                    .deactivate {
                        background: #b42318;
                    }
                    .activate {
                        background: #18794e;
                    }
                    .table-wrapper {
                        overflow-x: auto;
                        margin-top: 18px;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                    }
                    th, td {
                        text-align: left;
                        padding: 12px;
                        border-bottom: 1px solid #e0e5ed;
                    }
                    th {
                        background: #edf2fa;
                    }
                    a {
                        color: #183b70;
                        margin-right: 15px;
                    }
                    .note {
                        background: #fff6df;
                        padding: 12px;
                        border-radius: 6px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>TrustVault</h1>
                    <p>Administrator user management</p>

                    <h2>Create a User</h2>

                    <form method="post" action="/admin/users">
                        <input type="hidden" name="_csrf"
                               value="CSRF_TOKEN_PLACEHOLDER">

                        <label for="username">Username</label>
                        <input id="username" name="username"
                               required minlength="3" maxlength="40"
                               pattern="[A-Za-z0-9._-]+"
                               autocomplete="off">

                        <label for="password">Temporary Password</label>
                        <input id="password" name="password"
                               type="password" required
                               minlength="10" maxlength="72"
                               autocomplete="new-password">

                        <label for="role">User Role</label>
                        <select id="role" name="role" required>
                            <option value="OWNER">Document Owner</option>
                            <option value="VIEWER">Viewer</option>
                            <option value="ADMIN">Administrator</option>
                        </select>

                        <button class="create" type="submit">
                            Create User
                        </button>
                    </form>

                    <h2>Existing Users</h2>
                    <p>Review account roles and status below.</p>

                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                USER_ROWS_PLACEHOLDER
                            </tbody>
                        </table>
                    </div>

                    <p class="note">
                        Deactivation revokes document-sharing permissions.
                        Existing documents are preserved.
                    </p>

                    <p>
                        <a href="/admin">Back to Admin Dashboard</a>
                        <a href="/documents">Back to Documents</a>
                    </p>
                </div>
            </body>
            </html>
            """
            .replace("CSRF_TOKEN_PLACEHOLDER", token)
            .replace("USER_ROWS_PLACEHOLDER", rows.toString());
    }

    @PostMapping
    @ResponseBody
    public String createUser(
            Authentication authentication,
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String role) {

        if (!isAdmin(authentication)) {
            return messagePage("Access denied",
                    "Only active administrators can create users.");
        }

        username = username.trim();

        if (!username.matches("[A-Za-z0-9._-]{3,40}")) {
            return messagePage("Invalid username",
                    "Use 3-40 letters, numbers, dots, underscores or hyphens.");
        }

        if (password.length() < 10 || password.length() > 72) {
            return messagePage("Invalid password",
                    "Use a password between 10 and 72 characters.");
        }

        if (!"ADMIN".equals(role)
                && !"OWNER".equals(role)
                && !"VIEWER".equals(role)) {
            return messagePage("Invalid role", "Select a valid role.");
        }

        for (Useraccount existing : userRepository.findAll()) {
            if (username.equalsIgnoreCase(existing.getUsername())) {
                return messagePage("Username already exists",
                        "Choose a different username.");
            }
        }

        Useraccount newUser = new Useraccount();
        newUser.setUsername(username);
        newUser.setPasswordHash(passwordEncoder.encode(password));
        newUser.setRole(role);
        newUser.setEnabled(true);

        userRepository.save(newUser);

        auditLogService.log(
                authentication.getName(),
                "USER_CREATED",
                "Created account: " + username + ", role: " + role,
                "SUCCESS");

        return messagePage("User created successfully",
                "The account was created and its creation was recorded in the audit log.");
    }

    @PostMapping("/deactivate")
    @ResponseBody
    @Transactional
    public String deactivateUser(
            Authentication authentication,
            @RequestParam String username) {

        if (!isAdmin(authentication)) {
            return messagePage("Access denied",
                    "Only active administrators can deactivate accounts.");
        }

        Useraccount target = userRepository
                .findByUsername(username.trim())
                .orElse(null);

        if (target == null) {
            return messagePage("User not found",
                    "The requested account does not exist.");
        }

        if (!target.isEnabled()) {
            return messagePage("Account already inactive",
                    "This account is already deactivated.");
        }

        if ("ADMIN".equalsIgnoreCase(target.getRole())
                && countActiveAdmins() <= 1) {
            auditLogService.log(
                    authentication.getName(),
                    "USER_DEACTIVATION_BLOCKED",
                    "Attempted to deactivate the last active administrator",
                    "BLOCKED");

            return messagePage("Action blocked",
                    "The last active administrator cannot be deactivated.");
        }

        target.setEnabled(false);
        userRepository.save(target);

        permissionRepository.deleteByViewerUsername(target.getUsername());

        auditLogService.log(
                authentication.getName(),
                "USER_DEACTIVATED",
                "Deactivated account: " + target.getUsername(),
                "SUCCESS");

        return messagePage("Account deactivated",
                "The account was deactivated, sharing permissions were revoked, "
                + "and the action was recorded in the audit log.");
    }

    @PostMapping("/activate")
    @ResponseBody
    public String activateUser(
            Authentication authentication,
            @RequestParam String username) {

        if (!isAdmin(authentication)) {
            return messagePage("Access denied",
                    "Only active administrators can reactivate accounts.");
        }

        Useraccount target = userRepository
                .findByUsername(username.trim())
                .orElse(null);

        if (target == null) {
            return messagePage("User not found",
                    "The requested account does not exist.");
        }

        if (target.isEnabled()) {
            return messagePage("Account already active",
                    "This account is already active.");
        }

        target.setEnabled(true);
        userRepository.save(target);

        auditLogService.log(
                authentication.getName(),
                "USER_REACTIVATED",
                "Reactivated account: " + target.getUsername(),
                "SUCCESS");

        return messagePage("Account reactivated",
                "The account was reactivated and the action was recorded. "
                + "Previous sharing permissions were not restored automatically.");
    }

    private long countActiveAdmins() {
        return userRepository.findAll().stream()
                .filter(Useraccount::isEnabled)
                .filter(user -> "ADMIN".equalsIgnoreCase(user.getRole()))
                .count();
    }

    private String messagePage(String heading, String message) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport"
                      content="width=device-width, initial-scale=1">
                <title>TrustVault</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background: #f3f5f9;
                        padding: 30px;
                        color: #202b3c;
                    }
                    .container {
                        max-width: 650px;
                        margin: 30px auto;
                        background: white;
                        padding: 28px;
                        border-radius: 12px;
                    }
                    h2 { color: #183b70; }
                    a { color: #183b70; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>MESSAGE_HEADING</h2>
                    <p>MESSAGE_TEXT</p>
                    <p><a href="/admin/users">Return to User Management</a></p>
                    <p><a href="/documents">Return to Documents</a></p>
                </div>
            </body>
            </html>
            """
            .replace("MESSAGE_HEADING", escapeHtml(heading))
            .replace("MESSAGE_TEXT", escapeHtml(message));
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
