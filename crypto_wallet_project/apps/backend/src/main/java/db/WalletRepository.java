package db;

import java.sql.*;
import wallet.Wallet;

public class WalletRepository {
    public static void saveWallet(int userId, Wallet wallet) {
        String sql = """
                    INSERT INTO wallets (user_id, seed_phrase, currency, address, balance)
                    VALUES (?,?,?,?,?)
                """;
        try (Connection con = DatabaseManager.connect();
                PreparedStatement ptm = con.prepareStatement(sql)) {
            ptm.setInt(1, userId);
            ptm.setString(2, wallet.getSeedPhrase());
            ptm.setString(3, wallet.getCurrency());
            ptm.setString(4, wallet.getAddress());
            ptm.setDouble(5, wallet.getBalance());
            ptm.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
