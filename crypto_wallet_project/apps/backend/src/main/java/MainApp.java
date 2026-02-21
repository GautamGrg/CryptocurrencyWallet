import java.sql.*;
import java.util.Base64;
import java.util.Scanner;
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
    private static void register(String email, String password, String seed) {
        String hashed = hashPassword(password);
        String seedPhrase = MnemonicService.generateMnemonic();
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn.prepareStatement(
                        "INSERT INTO wallets(email, password_hash, seed_phrase) VALUES (?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, email);
            pstmt.setString(2, hashed);
            pstmt.setString(3, seedPhrase);
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

    private static void loginCred(String email, String password) {
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt = conn.prepareStatement("SELECT password_hash FROM wallets WHERE email = ?")) {
            pstmt.setString(1, email);
            ResultSet rs = pstmt.executeQuery();
            for (int i = 0; i < 3; i++) {
                if (rs.next()) {
                    String storedHash = rs.getString("password_hash");
                    if (validatePassword(password, storedHash)) {
                        System.out.println("Login successful.");
                    } else {
                        System.out.println("Invalid credentials. Attempt[" + i + "/3]");
                    }
                } else {
                    System.out.println("User not found.");
                }
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
            System.out.print("Password: ");
            String password = scanner.nextLine();
            System.out.print("Seed Phrase: ");
            String seed = scanner.nextLine();
            register(email, password, seed);
        } else {
            System.out.println("""
                    ======================================
                                User Login
                    ======================================
                    """);
            System.out.println("1. Login using user credentials\n 2. Recover account");
            int loginChoice = Integer.valueOf(scanner.nextLine());
            if (loginChoice == 1) {
                System.out.print("Email: ");
                String email = scanner.nextLine();
                System.out.print("Password: ");
                String password = scanner.nextLine();
                loginCred(email, password);
            } else {
                System.out.print("Seed Phrase: ");
                String seedPhrase = scanner.nextLine();
                loginSeed(seedPhrase);
            }

        }
        scanner.close();
    }
}
