package wallet;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.params.MainNetParams;

public class BitcoinWallet implements Wallet {

    private final String address;
    private double balance = 0.0;

    public BitcoinWallet() {
        ECKey key = new ECKey();
        this.address = LegacyAddress.fromKey(MainNetParams.get(), key).toString();
    }

    @Override
    public String getAddress() {
        return address;
    }

    @Override
    public String getCurrency() {
        return "BTC";
    }

    @Override
    public double getBalance() {
        return balance;
    }

    @Override
    public void credit(double amount) {
        balance += amount;
    }

    @Override
    public boolean debit(double amount) {
        if (balance >= amount) {
            balance -= amount;
            return true;
        }
        return false;
    }
}
