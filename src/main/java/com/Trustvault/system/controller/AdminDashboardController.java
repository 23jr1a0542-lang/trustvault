
package com.Trustvault.system.controller;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.repository.Useraccountrepository;

@Controller
public class AdminDashboardController {

    private final Useraccountrepository userRepository;

    public AdminDashboardController(
            Useraccountrepository userRepository) {
        this.userRepository = userRepository;
    }

    private boolean isAdmin(Authentication authentication) {

        if (authentication == null
                || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getName())) {
            return false;
        }

        Optional<Useraccount> user =
                userRepository.findByUsername(authentication.getName());

        return user.isPresent()
                && "ADMIN".equalsIgnoreCase(user.get().getRole())
                && Boolean.TRUE.equals(user.get().isEnabled());
    }

    @GetMapping("/admin")
    @ResponseBody
    public String adminDashboard(Authentication authentication) {

        if (!isAdmin(authentication)) {
            return """
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <title>Access Denied</title>
                    </head>
                    <body>
                        <h2>Access denied</h2>
                        <p>Only active administrators can open this page.</p>
                        <a href="/documents">Back to Documents</a>
                    </body>
                    </html>
                    """;
        }

        String username = escapeHtml(authentication.getName());

        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport"
                          content="width=device-width, initial-scale=1">
                    <title>TrustVault Admin Dashboard</title>

                    <style>
                        * {
                            box-sizing: border-box;
                        }

                        body {
                            font-family: Arial, sans-serif;
                            background: #f3f5f9;
                            color: #202b3c;
                            margin: 0;
                            padding: 30px;
                        }

                        .container {
                            max-width: 1100px;
                            margin: auto;
                        }

                        header {
                            background: #183b70;
                            color: white;
                            padding: 28px;
                            border-radius: 12px;
                            margin-bottom: 24px;
                        }

                        header h1 {
                            margin-top: 0;
                        }

                        .user-info {
                            font-size: 14px;
                            color: #e1eaff;
                        }

                        .cards {
                            display: grid;
                            grid-template-columns:
                                repeat(auto-fit, minmax(220px, 1fr));
                            gap: 18px;
                        }

                        .card {
                            background: white;
                            padding: 24px;
                            border-radius: 12px;
                            box-shadow: 0 3px 12px #00000012;
                            min-height: 220px;
                        }

                        .card h2 {
                            font-size: 20px;
                            margin-top: 0;
                        }

                        .card p {
                            line-height: 1.5;
                        }

                        .card a {
                            display: inline-block;
                            margin-top: 10px;
                            color: #183b70;
                            font-weight: bold;
                            text-decoration: underline;
                        }

                        .card a:hover {
                            color: #3459d5;
                        }

                        .status {
                            color: #667085;
                            font-size: 14px;
                        }

                        .footer {
                            margin-top: 24px;
                        }

                        .footer a {
                            color: #183b70;
                        }

                        @media (max-width: 600px) {
                            body {
                                padding: 15px;
                            }

                            header {
                                padding: 20px;
                            }
                        }
                    </style>
                </head>

                <body>
                    <div class="container">

                        <header>
                            <h1>TrustVault</h1>
                            <h2>Administrator Dashboard</h2>
                            <p>
                                Manage users and access your document system.
                            </p>
                            <p class="user-info">
                                Logged in as: <strong>""" + username + """
                                </strong> | Role: Administrator
                            </p>
                        </header>

                        <div class="cards">

                            <section class="card">
                                <h2>User Management</h2>
                                <p>
                                    Create user accounts, assign roles,
                                    and manage account status.
                                </p>
                                <a href="/admin/users">Manage Users</a>
                            </section>

                            <section class="card">
                                <h2>Document Management</h2>
                                <p>
                                    Open the document dashboard to view
                                    authorized documents and upload files.
                                </p>
                                <a href="/documents">View Documents</a>
                            </section>

                            <section class="card">
                                <h2>Permissions</h2>
                                <p>
                                    Access should follow each user's role
                                    and document-sharing permissions.
                                </p>
                                <p class="status">
                                    Permission changes must be enforced
                                    by the backend.
                                </p>
                            </section>

                            <section class="card">
                                <h2>Audit Logs</h2>
                                <p>
                                    Review recorded user activity and
                                    administrative actions.
                                </p>
                                <a href="/admin/audit-logs">
                                    View Audit Logs
                                </a>
                            </section>

                        </div>

                        <div class="footer">
                            <a href="/documents">Back to Documents</a>
                        </div>

                    </div>
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
