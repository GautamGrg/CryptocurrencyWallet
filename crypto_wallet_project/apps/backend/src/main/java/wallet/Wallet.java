package wallet;

public interface Wallet {
    String getSeedPhrase();
    String getAddress();
    String getCurrency();
    double getBalance();
}
