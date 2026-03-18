import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.SecureRandom;
import java.security.MessageDigest;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;

import db.DatabaseManager;
import db.WalletRepository;

import wallet.Wallet;
import wallet.BitcoinWallet;
import wallet.MnemonicService;

public class MainApp {
    private static void register(String email, char[] password) {
        String hashed = hashPassword(new String(password));
        String seedPhrase = MnemonicService.generateMnemonic();
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn.prepareStatement(
                        "INSERT INTO users(email, password_hash) VALUES (?, ?)",
                        Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, email);
            pstmt.setString(2, hashed);
            pstmt.executeUpdate();

            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                int userId = rs.getInt(1);
                Wallet btcWallet = new BitcoinWallet();
                WalletRepository.saveWallet(userId, btcWallet);

                System.out.println("Registration successful!");
                System.out.println("Seed phrase for account recovery: " + seedPhrase);
            }
        } catch (SQLException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static void loginCred(String email) {
        Console cnsl = System.console();
        if (cnsl == null) {
            System.out.println("No console available");
            return;
        }
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn.prepareStatement("SELECT password_hash FROM users WHERE email = ?")) {
            pstmt.setString(1, email);
            ResultSet rs = pstmt.executeQuery();
            int attempts_left = 1;
            if (rs.next()) {
                while (attempts_left <= 3) {
                    char[] password = cnsl.readPassword("Password: ");
                    String storedHash = rs.getString("password_hash");
                    if (validatePassword(new String(password), storedHash)) {
                        System.out.println("Login successful.");
                        break;
                    } else {
                        System.out.println("Invalid credentials. Attempt[" + attempts_left + "/3]");
                        attempts_left++;
                    }
                }
            }
            if (attempts_left > 3) {
                System.out.println("Exceeded number of password attempts. Login failed");
            }
        } catch (SQLException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static void loginSeed(String seedPhrase) {
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM wallets")) {
            pstmt.setString(3, seedPhrase);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                String storedSeed = rs.getString("seed_phrase");
                if (MnemonicService.validateMnemonic(storedSeed)) {
                    System.out.println("Account successfully recovered!");
                } else {
                    System.out.println("Entered invalid Seed Phrase");
                }
            }
        } catch (SQLException exc) {
            System.out.println("Error detected: " + exc.getMessage());
        }
    }

    private static String hashPassword(String password) {
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Hashing error: " + e.getMessage());
        }
    }

    private static boolean validatePassword(String password, String stored) {
        try {
            String[] parts = stored.split(":");
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] hash = Base64.getDecoder().decode(parts[1]);

            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] testHash = skf.generateSecret(spec).getEncoded();

            return MessageDigest.isEqual(hash, testHash);
        } catch (Exception e) {
            System.out.println("Password validation error: " + e.getMessage());
            return false;
        }
    }

    public static void main(String[] args) {
        DatabaseManager.init();
        Console cnsl = System.console();
        if (cnsl == null) {
            System.out.println("No console available");
            return;
        }
        Scanner scanner = new Scanner(System.in);
        System.out.println("""
                ==========================================
                        Welcome to Bitcoin Wallet
                ==========================================
                """);
        System.out.println("1. Register\n2. Login");
        System.out.print("Enter your choice: ");
        int choice = Integer.parseInt(scanner.nextLine());

        if (choice == 1) {
            System.out.println("""
                    \n====================================
                            Registering New user
                    ======================================
                    """);
            System.out.print("Email: ");
            String email = scanner.nextLine();
            char[] password = cnsl.readPassword("Password: ");
            register(email, password);
        } else {
            System.out.println("""
                    \n======================================
                                User Login
                    ======================================
                    """);
            System.out.println("1. Login using user credentials\n2. Recover account using Seed Phrase");
            System.out.print("Enter your choice: ");
            int loginChoice = Integer.valueOf(scanner.nextLine());
            if (loginChoice == 1) {
                System.out.print("Email: ");
                String email = scanner.nextLine();
                loginCred(email);
            } else {
                System.out.print("Seed Phrase: ");
                String seedPhrase = scanner.nextLine();
                loginSeed(seedPhrase);
            }
        }
        scanner.close();
    }
}
