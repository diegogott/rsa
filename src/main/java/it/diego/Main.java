package it.diego;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.Scanner;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger(Main.class);
    private static final String TOKEN = ";";

    public static void main(String[] args) {
        // Richiede il testo da criptare all'utente
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Inserisci il testo da criptare: ");
            String data = scanner.nextLine();

            // Procede con la generazione delle chiavi e la crittografia del testo
            rsaEncrypt(data);
        }
    }

    private static void rsaEncrypt(String data) {
        Random random = new Random();

        // Generazione di due numeri primi distinti
        BigInteger firstPrime = BigInteger.probablePrime(Long.BYTES, random);
        BigInteger secondPrime = BigInteger.probablePrime(Long.BYTES, random);

        // Controllo per evitare numeri primi uguali o un prodotto troppo piccolo
        while (firstPrime.equals(secondPrime) || firstPrime.multiply(secondPrime).compareTo(BigInteger.valueOf(30000)) <= 0) {
            firstPrime = BigInteger.probablePrime(Long.BYTES, random);
            secondPrime = BigInteger.probablePrime(Long.BYTES, random);
        }

        // Calcolo delle chiavi
        BigInteger n = firstPrime.multiply(secondPrime);
        BigInteger z = (firstPrime.subtract(BigInteger.ONE)).multiply(secondPrime.subtract(BigInteger.ONE));
        BigInteger e = coPrime(z);
        BigInteger d = computeD(e, z);

        // Log delle chiavi
        LOGGER.info("Chiave privata: d={}, n={}", d, n);
        LOGGER.info("Chiave pubblica: e={}, n={}", e, n);

        // Cripta il testo
        String encryptedText = encrypt(data, e, n);
        LOGGER.info("Testo criptato: {}", encryptedText);

        // Decripta il testo
        decrypt(encryptedText, d, n);
    }

    private static String encrypt(String data, BigInteger e, BigInteger n) {
        Vector<BigInteger> encryptedNumbers = new Vector<>();
        StringBuilder encryptedText = new StringBuilder();

        // Criptazione di ogni carattere
        for (char character : data.toCharArray()) {
            BigInteger encryptedChar = BigInteger.valueOf(character).modPow(e, n);
            encryptedNumbers.add(encryptedChar);
            encryptedText.append(encryptedChar).append(TOKEN);
        }

        LOGGER.info("Lista caratteri criptati: {}", encryptedNumbers);
        return encryptedText.toString();
    }

    private static void decrypt(String encryptedData, BigInteger d, BigInteger n) {
        StringTokenizer tokenizer = new StringTokenizer(encryptedData, TOKEN);
        StringBuilder decryptedText = new StringBuilder();
        Vector<BigInteger> decryptedNumbers = new Vector<>();

        // Decriptazione dei caratteri
        while (tokenizer.hasMoreTokens()) {
            BigInteger encryptedChar = new BigInteger(tokenizer.nextToken());
            BigInteger decryptedChar = encryptedChar.modPow(d, n);
            decryptedNumbers.add(decryptedChar);
            decryptedText.append((char) decryptedChar.intValueExact());
        }

        LOGGER.info("Lista caratteri decriptati: {}", decryptedNumbers);
        LOGGER.info("Testo decriptato: {}", decryptedText);
    }

    private static BigInteger computeD(BigInteger e, BigInteger z) {
        BigInteger d = BigInteger.TWO;
        while (!e.multiply(d).mod(z).equals(BigInteger.ONE)) {
            d = d.add(BigInteger.ONE);
        }
        return d;
    }

    private static BigInteger coPrime(BigInteger z) {
        Random random = new Random();
        BigInteger e;

        // Generazione di un coprimo
        do {
            e = BigInteger.probablePrime(Long.BYTES, random);
        } while (e.compareTo(z) >= 0 || !e.gcd(z).equals(BigInteger.ONE));

        return e;
    }
}
