package db;

import java.sql.*;
import wallet.Wallet;

public class WalletRepository {
    public static void saveWallet(int userId, Wallet wallet) {
        String sql = """
                    INSERT INTO wallets (address, currency, balance)
                    VALUES (?,?,?)
                """;
        try (Connection con = DatabaseManager.connect();
                PreparedStatement ptm = con.prepareStatement(sql)) {
            ptm.setString(1, wallet.getAddress());
            ptm.setString(2, wallet.getCurrency());
            ptm.setDouble(3, wallet.getBalance());
            ptm.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
