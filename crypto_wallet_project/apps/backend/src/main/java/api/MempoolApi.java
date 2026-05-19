/* (C)2026 */
package api;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import org.bouncycastle.util.encoders.Hex;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public class MempoolApi {
    public static HttpClient client = HttpClient.newHttpClient();
    public static ObjectMapper objectMapper = new ObjectMapper();

    // We first send a GET request to verify if address is valid
    public static Boolean getIsValid(String address) throws IOException, InterruptedException {
        HttpRequest getIsValid =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        "https://mempool.space/testnet/api/v1/validate-address/"
                                                + address))
                        .GET()
                        .build();
        HttpResponse<String> getResponse = client.send(getIsValid, BodyHandlers.ofString());
        String response = getResponse.body();
        JsonNode node = objectMapper.readTree(response);

        return node.get("isvalid").asBoolean();
    }

    // Before sending coins to the verified address, we need to GET utxos
    // available coins we can send to the recipient.
    public static String getUtxo(String address) throws IOException, InterruptedException {
        HttpRequest getUtxo =
                HttpRequest.newBuilder()
                        .uri(
                                URI.create(
                                        "https://mempool.space/testnet/api/address/"
                                                + address
                                                + "/utxo"))
                        .GET()
                        .build();
        HttpResponse<String> getResponse = client.send(getUtxo, BodyHandlers.ofString());

        return getResponse.body();
    }

    // This POST request will broadcast a raw transaction to the testnet network.
    // This will return txid in String
    public static String broadcastTransaction(String txHex) throws IOException, InterruptedException {
        HttpRequest postTrans =
                HttpRequest.newBuilder()
                        .uri(URI.create("https://mempool.space/testnet/api/tx"))
                        .POST(HttpRequest.BodyPublishers.ofString(txHex))
                        .build();
        HttpResponse<String> getResponse = client.send(postTrans, BodyHandlers.ofString());
        int code = getResponse.statusCode();
        System.out.println("Transaction broadcast status code: " + code);
        return getResponse.body();
    }

    public static double getRecommFees()
            throws IOException, InterruptedException { // Returns value in sat/vb
        HttpRequest getFees =
                HttpRequest.newBuilder()
                        .uri(URI.create("https://mempool.space/testnet/api/v1/fees/precise"))
                        .GET()
                        .build();
        HttpResponse<String> getResponse = client.send(getFees, BodyHandlers.ofString());
        String fastestFee = getResponse.body();
        JsonNode feeNode = objectMapper.readTree(fastestFee);

        return feeNode.get("fastestFee").asDouble();
    }
}
