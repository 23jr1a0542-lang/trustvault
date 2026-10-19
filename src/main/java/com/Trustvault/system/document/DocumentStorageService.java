
package com.Trustvault.system.document;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class DocumentStorageService {

    private final Path storageDirectory;

    public DocumentStorageService(
            @Value("${trustvault.storage-dir:trustvault-files}")
            String storageDirectory) throws IOException {

        this.storageDirectory = Paths.get(storageDirectory)
                .toAbsolutePath()
                .normalize();

        Files.createDirectories(this.storageDirectory);
    }

    public String store(MultipartFile file) throws IOException {

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Please select a file.");
        }

        String originalName = file.getOriginalFilename();

        if (originalName == null || originalName.isBlank()) {
            throw new IllegalArgumentException("Invalid file name.");
        }

        // Do not trust a filename containing directory paths.
        String safeName = Paths.get(originalName)
                .getFileName()
                .toString();

        if (safeName.isBlank() || safeName.contains("..")) {
            throw new IllegalArgumentException("Invalid file name.");
        }

        // Store using a random server-side name.
        String storedName = UUID.randomUUID().toString();
        Path destination = storageDirectory.resolve(storedName).normalize();

        if (!destination.startsWith(storageDirectory)) {
            throw new IllegalArgumentException("Invalid storage path.");
        }

        try (InputStream input = file.getInputStream()) {
            Files.copy(input, destination, StandardCopyOption.REPLACE_EXISTING);
        }

        return destination.toString();
    }
}
