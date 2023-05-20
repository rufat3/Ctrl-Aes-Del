import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class AES {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Get input from user
        System.out.println("Choose an option:");
        System.out.println("1. Encrypt plaintext");
        System.out.println("2. Decrypt cipher");
        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume the newline character

        SecretKey secretKey;

        if (choice == 1) {
            System.out.println("Choose an option:");
            System.out.println("1. Generate encryption key");
            System.out.println("2. Enter encryption key");
            System.out.print("Enter your choice: ");
            int keyOption = scanner.nextInt();
            scanner.nextLine(); // Consume the newline character

            if (keyOption == 1) {
                secretKey = generateKey();
                System.out.println("Generated encryption key: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            } else if (keyOption == 2) {
                System.out.print("Enter encryption key (base64 encoded): ");
                String encodedKey = scanner.nextLine();
                byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
                secretKey = new SecretKeySpec(keyBytes, "AES");
            } else {
                System.out.println("Invalid choice.");
                return;
            }

            // Get input from user
            System.out.print("Enter plaintext: ");
            String plaintext = scanner.nextLine();

            // Choose encryption mode
            System.out.println("Choose encryption mode: ");
            System.out.println("1. AES-ECB");
            System.out.println("2. AES-CBC");
            System.out.println("3. AES-CTR");
            System.out.print("Enter your choice: ");
            int modeChoice = scanner.nextInt();

            // Encrypt plaintext using the selected mode
            String encryptedText;
            switch (modeChoice) {
                case 1 -> encryptedText = encryptECB(plaintext, secretKey);
                case 2 -> encryptedText = encryptCBC(plaintext, secretKey);
                case 3 -> encryptedText = encryptCTR(plaintext, secretKey);
                default -> {
                    System.out.println("Invalid choice.");
                    return;
                }
            }

            System.out.println("Encrypted text: " + encryptedText);
        } else if (choice == 2) {
            System.out.print("Enter encryption key (base64 encoded): ");
            String encodedKey = scanner.nextLine();
            byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
            secretKey = new SecretKeySpec(keyBytes, "AES");

            // Get input from user
            System.out.print("Enter cipher (base64 encoded): ");
            String cipherText = scanner.nextLine();

            // Choose decryption mode
            System.out.println("Choose decryption mode: ");
            System.out.println("1. AES-ECB");
            System.out.println("2. AES-CBC");
            System.out.println("3. AES-CTR");
            System.out.print("Enter your choice: ");
            int modeChoice = scanner.nextInt();

            // Decrypt cipher using the selected mode
            String decryptedText;
            switch (modeChoice) {
                case 1 -> decryptedText = decryptECB(cipherText, secretKey);
                case 2 -> decryptedText = decryptCBC(cipherText, secretKey);
                case 3 -> decryptedText = decryptCTR(cipherText, secretKey);
                default -> {
                    System.out.println("Invalid choice.");
                    return;
                }
            }

            System.out.println("Decrypted text: " + decryptedText);
        } else {
            System.out.println("Invalid choice.");
        }
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static String encryptECB(String plaintext, SecretKey secretKey) throws Exception {
        byte[] encryptedBytes = aesEncrypt(plaintext.getBytes(StandardCharsets.UTF_8), secretKey, "AES/ECB/PKCS5Padding");
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptECB(String cipherText, SecretKey secretKey) throws Exception {
        byte[] decryptedBytes = aesDecrypt(Base64.getDecoder().decode(cipherText), secretKey, "AES/ECB/PKCS5Padding");
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static String encryptCBC(String plaintext, SecretKey secretKey) throws Exception {
        byte[] iv = generateIV(16); // 16 bytes IV for AES-CBC
        byte[] encryptedBytes = aesEncrypt(plaintext.getBytes(StandardCharsets.UTF_8), secretKey, "AES/CBC/PKCS5Padding", iv);
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decryptCBC(String cipherText, SecretKey secretKey) throws Exception {
        byte[] combined = Base64.getDecoder().decode(cipherText);
        byte[] iv = new byte[16]; // 16 bytes IV for AES-CBC
        byte[] encryptedBytes = new byte[combined.length - iv.length];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);
        byte[] decryptedBytes = aesDecrypt(encryptedBytes, secretKey, "AES/CBC/PKCS5Padding", iv);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static String encryptCTR(String plaintext, SecretKey secretKey) throws Exception {
        byte[] iv = generateIV(16); // 16 bytes IV for AES-CTR
        byte[] encryptedBytes = aesEncrypt(plaintext.getBytes(StandardCharsets.UTF_8), secretKey, "AES/CTR/NoPadding", iv);
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decryptCTR(String cipherText, SecretKey secretKey) throws Exception {
        byte[] combined = Base64.getDecoder().decode(cipherText);
        byte[] iv = new byte[16]; // 16 bytes IV for AES-CTR
        byte[] encryptedBytes = new byte[combined.length - iv.length];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);
        byte[] decryptedBytes = aesDecrypt(encryptedBytes, secretKey, "AES/CTR/NoPadding", iv);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static byte[] aesEncrypt(byte[] input, SecretKey secretKey, String cipherAlgorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(input);
    }

    public static byte[] aesEncrypt(byte[] input, SecretKey secretKey, String cipherAlgorithm, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(input);
    }

    public static byte[] aesDecrypt(byte[] input, SecretKey secretKey, String cipherAlgorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(input);
    }

    public static byte[] aesDecrypt(byte[] input, SecretKey secretKey, String cipherAlgorithm, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(input);
    }

    public static byte[] generateIV(int length) {
        byte[] iv = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
}
