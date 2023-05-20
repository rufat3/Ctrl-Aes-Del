import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class AES {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Generate encryption key
        SecretKey secretKey = generateKey();

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
        String encryptedText = "";
        switch (modeChoice) {
            case 1 -> encryptedText = encryptECB(plaintext, secretKey);
            case 2 -> encryptedText = encryptCBC(plaintext, secretKey);
            case 3 -> encryptedText = encryptCTR(plaintext, secretKey);
            default -> {
                System.out.println("Invalid choice.");
                System.exit(0);
            }
        }

        System.out.println("Encrypted text: " + encryptedText);

        // Get input from user
        System.out.print("\nEnter cipher (base64 encoded): ");
        String cipherText = scanner.next();

        // Decrypt cipher using the selected mode
        String decryptedText = "";
        switch (modeChoice) {
            case 1 -> decryptedText = decryptECB(cipherText, secretKey);
            case 2 -> decryptedText = decryptCBC(cipherText, secretKey);
            case 3 -> decryptedText = decryptCTR(cipherText, secretKey);
            default -> {
                System.out.println("Invalid choice.");
                System.exit(0);
            }
        }

        System.out.println("Decrypted text: " + decryptedText);
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

    public static byte[] aesEncrypt(byte[] plaintextBytes, SecretKey secretKey, String transformation) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintextBytes);
    }

    public static byte[] aesEncrypt(byte[] plaintextBytes, SecretKey secretKey, String transformation, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(plaintextBytes);
    }

    public static byte[] aesDecrypt(byte[] cipherBytes, SecretKey secretKey, String transformation) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(cipherBytes);
    }

    public static byte[] aesDecrypt(byte[] cipherBytes, SecretKey secretKey, String transformation, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(cipherBytes);
    }

    public static byte[] generateIV(int length) {
        byte[] iv = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
}
