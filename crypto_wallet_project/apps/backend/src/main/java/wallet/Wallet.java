package wallet;

public interface Wallet {
    String getEmail();
    String getPassword();
    String getSeedPhrase();
    String getAddress();
    String getCurrency();
    double getBalance();
    void credit(double amount);
    boolean debit(double amount);
}
