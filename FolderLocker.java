import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class FolderLocker {
    private static final String ALGORITHM = "AES";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String LOCK_EXTENSION = ".lock";
    private static final byte[] DEFAULT_KEY = "SomeSecretKey123".getBytes();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the folder path to lock: ");
        String folderPath = scanner.nextLine();

        System.out.print("Enter the password: ");
        String password = scanner.nextLine();

        if (lockFolder(folderPath, password)) {
            System.out.println("Folder locked successfully!");
        } else {
            System.out.println("Failed to lock the folder.");
        }

        scanner.close();
    }

    public static boolean lockFolder(String folderPath, String password) {
        try {
            File folder = new File(folderPath);

            if (!folder.exists() || !folder.isDirectory()) {
                System.out.println("Invalid folder path.");
                return false;
            }

            String lockFilePath = folderPath + File.separator + folder.getName() + LOCK_EXTENSION;
            File lockFile = new File(lockFilePath);

            if (lockFile.exists()) {
                System.out.println("Folder is already locked.");
                return false;
            }

            byte[] key = generateKey(password);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGORITHM));

            Files.createFile(Paths.get(lockFilePath));

            encryptFilesInDirectory(folder, cipher);

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static void encryptFilesInDirectory(File directory, Cipher cipher) throws Exception {
        for (File file : directory.listFiles()) {
            if (file.isFile()) {
                encryptFile(file, cipher);
                file.delete();
            } else if (file.isDirectory()) {
                encryptFilesInDirectory(file, cipher);
                file.delete();
            }
        }
    }

    private static void encryptFile(File file, Cipher cipher) throws Exception {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        byte[] encryptedBytes = cipher.doFinal(fileBytes);
        Files.write(file.toPath(), encryptedBytes);
    }

    private static byte[] generateKey(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] hashedPassword = digest.digest(password.getBytes());
        return Arrays.copyOf(hashedPassword, 16); // AES key size is 16 bytes
    }
}
