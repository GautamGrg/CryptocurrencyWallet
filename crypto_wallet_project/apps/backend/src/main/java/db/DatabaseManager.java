package db;

import java.sql.Statement;
import java.sql.Connection;
import java.sql.DriverManager;

public class DatabaseManager {
    private static final String DB_URL = "jdbc:sqlite:crypto_wallet_db.db";

    public static Connection connect() {
        try {
            Connection con = DriverManager.getConnection(DB_URL);
            return con;
        } catch (Exception exc) {
            System.out.println("Database connection failed due to: " + exc.getMessage());
            return null;
        }
    }

    public static void init() {
        try (Connection con = connect(); Statement stm = con.createStatement()) {
            stm.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    seed_phrase TEXT NOT NULL
                )
            """);
            stm.execute("""
                CREATE TABLE IF NOT EXISTS wallets(
                    user_id INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    address TEXT NOT NULL,
                    balance REAL DEFAULT 0
                )
            """);
            System.out.println("Database created successfully!");
        } catch (Exception exc) {
            System.out.println("Database init error: " + exc.getMessage());
            exc.printStackTrace();
        }
    }
}
