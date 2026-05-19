/* (C)2026 */
import api.MempoolApi;
import com.google.protobuf.InvalidProtocolBufferException;
import db.DatabaseManager;
import db.WalletRepository;
import java.io.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.crypto.EncryptedData;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.Script;
import org.bitcoinj.wallet.Protos.ScryptParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import wallet.BitcoinWallet;
import wallet.MnemonicService;

public class MainApp {
    private static final Logger logger = LogManager.getLogger(MainApp.class);
    public static ObjectMapper objectMapper = new ObjectMapper();

    private static void register(String email, String hashPassword) {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        Date date = new Date(timestamp.getTime());
        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy' 'HH:mm:ss");
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt =
                        conn.prepareStatement("SELECT * FROM users WHERE email = ?")) {
            pstmt.setString(1, email);
            ResultSet rs = pstmt.executeQuery();
            if (!rs.next()) {
                try (PreparedStatement pstmt_ =
                        conn.prepareStatement(
                                "INSERT INTO users(email, password_hash, created_date) VALUES (?,"
                                        + " ?, ?)",
                                Statement.RETURN_GENERATED_KEYS)) {
                    pstmt_.setString(1, email);
                    pstmt_.setString(2, hashPassword);
                    pstmt_.setString(3, sdf.format(date));
                    pstmt_.executeUpdate();

                    ResultSet rs_ = pstmt_.getGeneratedKeys();
                    if (rs_.next()) {
                        int userId = rs_.getInt(1);
                        BitcoinWallet btcWallet = new BitcoinWallet(hashPassword, null);
                        String seedPhrase = btcWallet.getSeedPhrase();
                        WalletRepository.saveWallet(userId, btcWallet);
                        logger.info("Registration successful!");
                        logger.info("Seed phrase for account recovery: " + seedPhrase);
                    }
                } catch (SQLException e) {
                    logger.error("Error: " + e.getMessage());
                }
            } else {
                logger.warn("Email is already registered!");
            }
        } catch (SQLException e) {
            logger.error("Error: " + e.getMessage());
        }
    }

    private static String loginCred(String email, Scanner scanner) {
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt =
                        conn.prepareStatement(
                                "SELECT id, password_hash FROM users WHERE email = ?")) {
            pstmt.setString(1, email);
            ResultSet rs = pstmt.executeQuery();
            if (!rs.next()) {
                logger.warn(
                        "Invalid user, either you entered wrong email or the user is not"
                                + " registered");
                return null;
            }
            int userId = rs.getInt("id");
            for (int attempt = 1; attempt <= 3; attempt++) {
                System.out.print("Password: ");
                char[] password = scanner.nextLine().toCharArray();
                String storedHash = rs.getString("password_hash");
                if (validatePassword(new String(password), storedHash)) {
                    logger.info("Login successful.");
                    try (PreparedStatement pstmt_ =
                            conn.prepareStatement(
                                    "SELECT address FROM wallets WHERE user_id = ?")) {
                        pstmt_.setInt(1, userId);
                        ResultSet rs_ = pstmt_.executeQuery();
                        if (rs_.next()) {
                            return rs_.getString("address");
                        }
                    }
                } else {
                    logger.warn("Invalid credentials. Attempt[" + attempt + "/3]");
                }
            }
            logger.warn("Exceeded number of password attempts...");
            return null;
        } catch (SQLException e) {
            logger.error("Error: " + e.getMessage());
            return null;
        }
    }

    private static String hashPassword(String password) {
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(salt)
                    + ":"
                    + Base64.getEncoder().encodeToString(hash);
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
            logger.error("Password validation error: " + e.getMessage());
            return false;
        }
    }

    private static void recoverWallet(Scanner scanner, Console cnsl) {
        boolean validSeedPhrase = false;
        String seedPhrase = null;

        for (int i = 0; i <= 3; i++) {
            System.out.print("Please enter your wallet recovery Phrase: ");
            String seedPhrasePrefix = scanner.nextLine().trim().toLowerCase();
            if (!MnemonicService.validateMnemonic(seedPhrasePrefix)) {
                logger.warn("Entered invalid Seed Phrase!");
            } else {
                seedPhrase = seedPhrasePrefix;
                validSeedPhrase = true;
                break;
            }
        }
        if (!validSeedPhrase) {
            throw new java.lang.Error("You have reached the number of attempts!");
        }
        char[] newPassword = cnsl.readPassword("Please enter your new password: ");
        String hashed = hashPassword(new String(newPassword));
        // Zero out the possible password, for security purposes
        Arrays.fill(newPassword, '\0');

        BitcoinWallet btcwallet = new BitcoinWallet(hashed, seedPhrase);
        try (Connection conn = DatabaseManager.connect()) {
            PreparedStatement pstmt =
                    conn.prepareStatement(
                            "UPDATE wallets SET scrypt_param_bytes"
                                    + " =?,encrypted_private_key_bytes =?,"
                                    + " encrypted_private_key_ivector=? WHERE address = ?");
            pstmt.setBytes(1, btcwallet.getScryptParamBytes());
            pstmt.setBytes(2, btcwallet.getEncryptedPrivKeyBytes());
            pstmt.setBytes(3, btcwallet.getEncryptedPrivKeyIvector());
            pstmt.setString(4, btcwallet.getAddress());
            int updateWallets = pstmt.executeUpdate();

            if (updateWallets == 0) {
                logger.error("Failed to locate user Public address");
            } else {
                PreparedStatement pstmt_ =
                        conn.prepareStatement(
                                "UPDATE users SET password_hash = ? WHERE id = (SELECT user_id FROM"
                                        + " wallets WHERE address =?)");
                pstmt_.setString(1, hashed);
                pstmt_.setString(2, btcwallet.getAddress());
                int updateUsers = pstmt_.executeUpdate();

                if (updateUsers == 0) {
                    logger.error("Failed to update password.");
                } else {
                    logger.info("Successfully recovered wallet!");
                }
            }
        } catch (SQLException e) {
            logger.error("Error: " + e.getMessage());
        }
    }

    private static void userWallet(String address) {
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt =
                        conn.prepareStatement(
                                "SELECT currency, balance FROM wallets WHERE address = ?")) {
            pstmt.setString(1, address);
            ResultSet rs = pstmt.executeQuery();
            logger.info("\n----- Wallet Balances -----");
            boolean foundWallet = false;
            if (rs.next()) {
                foundWallet = true;
                String currency = rs.getString("currency");
                double balance = rs.getDouble("balance");
                logger.info(currency + ":" + balance);
            }
            if (!foundWallet) {
                logger.error("No wallets found");
            }
        } catch (SQLException e) {
            logger.error("Error: " + e.getMessage());
        }
    }

    private static void refreshBalance(String address) throws IOException, InterruptedException {
        String utxo = MempoolApi.getUtxo(address);
        JsonNode utxoNode = objectMapper.readTree(utxo);

        long userSatoshi = 0;
        if (utxoNode.isArray()) {
            for (int i = 0; i < utxoNode.size(); i++) {
                userSatoshi += utxoNode.get(i).get("value").asLong();
            }
        }
        double btcBalance = (userSatoshi / (double) Math.pow(10, 8));
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt =
                        conn.prepareStatement("UPDATE wallets SET balance = ? WHERE address = ?")) {
            pstmt.setDouble(1, btcBalance);
            pstmt.setString(2, address);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            logger.error("Error raised by: " + e.getMessage());
        }
    }

    private static boolean transactionSend(double amount, String senderAddress, String recpientAddress)
            throws InvalidProtocolBufferException, IOException, InterruptedException, SQLException {
        try (Connection conn = DatabaseManager.connect();
                PreparedStatement pstmt =
                        conn.prepareStatement(
                                "SELECT scrypt_param_bytes, public_key_bytes,"
                                    + " encrypted_private_key_bytes, encrypted_private_key_ivector,"
                                    + " user_id FROM wallets WHERE address = ?")) {
            pstmt.setString(1, senderAddress);
            ResultSet rs = pstmt.executeQuery();
            if (!rs.next()) {
                throw new java.lang.Error("An Error occured retrieving user details");
            }
            int userId = rs.getInt("user_id");
            byte[] kcsParamBytes = rs.getBytes("scrypt_param_bytes");
            byte[] pubKeyBytes = rs.getBytes("public_key_bytes");
            byte[] encryptedPrivBytes = rs.getBytes("encrypted_private_key_bytes");
            byte[] encryptedPrivKeyIvector = rs.getBytes("encrypted_private_key_ivector");

            try(PreparedStatement pstmtUser =
                    conn.prepareStatement("SELECT password_hash FROM users WHERE id = ?")){
            pstmtUser.setInt(1, userId);
            ResultSet rsUser = pstmtUser.executeQuery();
            if (!rsUser.next()) {
                logger.error("User does not have a registered wallet");
            }
            String userPasswordHash = rsUser.getString("password_hash");

            // We inherit the KeyCrypterScrypt parameters used previously to derive the AESKey
            // for encryption. So that it retains the same salt for the decryption process.
            ScryptParameters kcsParameters = ScryptParameters.parseFrom(kcsParamBytes);
            KeyCrypterScrypt crypt = new KeyCrypterScrypt(kcsParameters);
            // Derieve the AESkey for decrypting the private key
            KeyParameter aesKey = crypt.deriveKey(userPasswordHash);
            // Holder for encrypted values for private key bytes and private key I-vector
            // preparations for decrypting the private key
            EncryptedData encryptedData =
                    new EncryptedData(encryptedPrivKeyIvector,encryptedPrivBytes);

            // The fromEncrypted method constructs a key using the private key
            // components (private key bytes and initialisation vector). The returned
            // ECKey will be used for digital signing after decryption
            ECKey encryptedPrivKey = ECKey.fromEncrypted(encryptedData, crypt, pubKeyBytes);
            // Decrypt the private key using the KeyCrypter and AESkey dervied from
            // the hashed password
            ECKey decryptedPrivKey = encryptedPrivKey.decrypt(crypt, aesKey);

            NetworkParameters netParam = TestNet3Params.get();
            Transaction tx = new Transaction(netParam);

            // Check if the recipient address is a valid P2PKH address
            boolean addressIsValid = MempoolApi.getIsValid(recpientAddress);
            if (addressIsValid) {
                // Convert transfer amount BTC to Satoshi Coin representation
                long amountInSatoshi = (long) (amount * (long) Math.pow(10, 8));
                Coin coin = Coin.valueOf(amountInSatoshi);

                // Assume input size to be 1 and output as (recipient count + 1)
                int input = 0;
                int output = 2;

                Address senderAddressBytes = Address.fromString(netParam, senderAddress);
                Address recipeintAddressBytes = Address.fromString(netParam, recpientAddress);
                tx.addOutput(coin, recipeintAddressBytes);

                // We calculate the intial / estimated fee using tx size * fastestFeeRate in
                // sat/VByte
                long feeSatoshi =
                        ((long) (MempoolApi.getRecommFees())
                                * (10 + (input * 148) + (output * 34)));
                long amountPlusFee = feeSatoshi + amountInSatoshi;

                long userSatoshi = 0;
                final double fastestFees = MempoolApi.getRecommFees();
                JsonNode utxoNode = objectMapper.readTree(MempoolApi.getUtxo(senderAddress));
                if (utxoNode.isArray()) {
                    for (JsonNode utxo : utxoNode) {
                        if (userSatoshi <= amountPlusFee) {
                            userSatoshi += utxo.get("value").asLong();
                            input++;
                            // Re-calculate estimated transaction fees and total amount required to
                            // sign transaction
                            feeSatoshi =
                                    ((long) (fastestFees)
                                            * (10 + (input * 148) + (output * 34)));
                            amountPlusFee = feeSatoshi + amountInSatoshi;
                            // Retrieve the previous transaction ID and vout value (transaction
                            // index)
                            long prevVout = utxo.get("vout").asLong();
                            String prevTxid = utxo.get("txid").asString();
                            Sha256Hash prevTxidHash = Sha256Hash.wrap(Hex.decode(prevTxid));
                            // The transaction outpoint is used to reference a previous transaction
                            TransactionOutPoint txOutPoint =
                                    new TransactionOutPoint(netParam, prevVout, prevTxidHash);
                            tx.addInput(
                                    new TransactionInput(
                                            netParam,
                                            tx,
                                            new byte[] {},
                                            txOutPoint,
                                            Coin.valueOf(utxo.get("value").asLong())));
                        } else {
                            break;
                        }
                    }   
                    if (userSatoshi < amountPlusFee) {
                        logger.error("Insufficient funds to send!");
                        return false;
                    }
                }
                // If the change output is less than dust threshold (P2PKH is ~ 546 sat/vB)
                long satoshiChange = userSatoshi - amountInSatoshi - feeSatoshi;
                if (satoshiChange > 546) {
                    tx.addOutput(Coin.valueOf(satoshiChange), senderAddressBytes);
                } 

                // Signing each input in the transaction
                Script scriptPubKey = ScriptBuilder.createOutputScript(Address.fromString(netParam, senderAddress));
                for (int i = 0; i < tx.getInputs().size(); i ++){
                    TransactionSignature sig = tx.calculateSignature(i, decryptedPrivKey, scriptPubKey, Transaction.SigHash.ALL, false);
                    tx.getInput(i).setScriptSig(ScriptBuilder.createInputScript(sig, decryptedPrivKey));
                }
                String txHex = Hex.toHexString(tx.bitcoinSerialize());
                String txId = MempoolApi.broadcastTransaction(txHex);
                if (txId.length() != 0){
                    logger.info("Transaction broadcast successful. TXID response: " + txId);
                    return true;
                }return false;
            }
        } catch (SQLException exc) {
            logger.error("Error caused by: " + exc);
            return false;
            }
        }
        return true; 
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        DatabaseManager.init();
        Console cnsl = System.console();
        if (cnsl == null) {
            logger.error("No console available");
            return;
        }
        Scanner scanner = new Scanner(System.in);
        System.out.println(
                """
                ==========================================
                        Welcome to Bitcoin Wallet
                ==========================================
                """);
        System.out.println("1. Register\n2. Login");
        System.out.print("Enter your choice: ");
        int choice = Integer.parseInt(scanner.nextLine());

        if (choice == 1) {
            System.out.println(
                    """
                    \n====================================
                            Registering New user
                    ====================================
                    """);
            System.out.print("Email: ");
            String email = scanner.nextLine().toLowerCase();
            char[] password = cnsl.readPassword("Password: ");
            String hashed = hashPassword(new String(password));
            Arrays.fill(password, '\0');

            register(email, hashed);
        } else {
            System.out.println(
                    """
                    \n======================================
                                User Login
                    ======================================
                    """);
            System.out.println(
                    "1. Login using user credentials\n2. Recover account using Seed Phrase");
            System.out.print("Enter your choice: ");
            int loginChoice = Integer.parseInt(scanner.nextLine());
            if (loginChoice == 1) {
                System.out.print("\nEmail: ");
                String email = scanner.nextLine();
                String userAddress = loginCred(email, scanner);
                // scanner.nextLine(); // consume leftover newline from Console.readPassword
                if (userAddress != null) {
                    System.out.println(
                            """
                    \n======================================
                                Account Menu
                    ======================================
                    """);
                    refreshBalance(userAddress);
                    System.out.println("1. Check account balance \n2. Send BTC");
                    System.out.print("Enter your choice: ");
                    int menuOption = Integer.parseInt(scanner.nextLine());
                    if (menuOption == 1) {
                        userWallet(userAddress);
                    } else if (menuOption == 2) {
                        System.out.print("\nEnter the recipient's public address: ");
                        String recpientAddress = scanner.nextLine();
                        System.out.print("\nEnter the amount of BTC to send: ");
                        double amount = scanner.nextDouble();

                        try {
                            if(transactionSend(amount, userAddress, recpientAddress)){
                                logger.info("Successfully sent BTC: " + amount + " to recipient address: " + recpientAddress);
                            }
                        } catch (InvalidProtocolBufferException | SQLException exc) {
                            logger.error("The following error was raised due to: " + exc);
                        }
                    } else {
                        logger.error("Please enter a vaild option");
                    }
                } else {
                    logger.error("Login failed!");
                }
            } else {
                recoverWallet(scanner, cnsl);
            }
        }
        scanner.close();
    }
}
