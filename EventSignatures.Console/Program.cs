﻿using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Tsp;
using Sodium;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

Console.WriteLine("Loading json data...");

string jsonPath = "./Data/ObjectEvent.jsonld";
string hashUrl = "http://127.0.0.1:5000/hash";

// Load the epcis event data
var eventJson = File.ReadAllText(jsonPath);

// Generate the EPCIS Event Hash
var httpClient = new HttpClient();
httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
var hashRequest = new HttpRequestMessage(HttpMethod.Post, hashUrl);
hashRequest.Content = new StringContent(eventJson, Encoding.UTF8, "application/json");
var response = await httpClient.SendAsync(hashRequest);
var eventHash = await response.Content.ReadAsStringAsync();
Console.WriteLine($"Generated Event Hash:\n {eventHash}");

// Generate an ED25519 public-private key pair
KeyPair keyPair = PublicKeyAuth.GenerateKeyPair();

// Extract the public and private keys
byte[] publicKey = keyPair.PublicKey;
byte[] privateKey = keyPair.PrivateKey;

// Convert keys to base64 for storage or transmission
string publicKeyBase64 = Convert.ToBase64String(publicKey);
string privateKeyBase64 = Convert.ToBase64String(privateKey);

Console.WriteLine("Generated Public Key (Base64):");
Console.WriteLine(publicKeyBase64);
Console.WriteLine("\n Generated Private Key (Base64):");
Console.WriteLine(privateKeyBase64);

// Generate the DID document for exposing the public key
var didDocument = new DIDDocument()
{
    id = "https://example.org/digitallink/urn:gdst:example.org:party:test.test",
    verificationMethod = new VerificationMethod()
    {
        id = "https://example.org/digitallink/urn:gdst:example.org:party:test.test#key-1",
        type = "Ed25519VerificationKey2018", 
        publicKeyBase64 = publicKeyBase64
    }
};

// Generate a nonce (a unique value for each encryption)
byte[] nonce = PublicKeyBox.GenerateNonce();

// Encrypt the event hash using the public key and nonce
byte[] encryptedHash = PublicKeyBox.Create("test", nonce, keyPair.PrivateKey, keyPair.PublicKey);

// Store the event hash as a base64 string
string nonceBase64 = Convert.ToBase64String(nonce);
string encryptedHashBase64 = Convert.ToBase64String(encryptedHash);

// Format the byte array to be time stamped
Sha512Digest digest = new Sha512Digest();
byte[] dataToTimestamp = Encoding.ASCII.GetBytes(eventHash);
int readLength = dataToTimestamp.Length;
digest.BlockUpdate(dataToTimestamp, 0, readLength);
byte[] result = new byte[digest.GetDigestSize()];
digest.DoFinal(result, 0);

// Generate a timestamp query
TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
tsqGenerator.SetCertReq(false); // Request the TSA certificate
TimeStampRequest tsq = tsqGenerator.Generate(TspAlgorithms.Sha512, result);

// Convert the timestamp query to bytes
byte[] tsqBytes = tsq.GetEncoded();

// Send the time stamp request to a trusted Time Stamping Authority
string timestamp = string.Empty;
HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://freetsa.org/tsr");
using (var stream = new MemoryStream(tsqBytes))
{
    hashRequest.Content = new StreamContent(stream);
    hashRequest.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");
    var timestampResponse = await httpClient.SendAsync(hashRequest);
    var test = timestampResponse.Content.ReadAsStringAsync();
    using (var reader = new StreamReader(timestampResponse.Content.ReadAsStream()))
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(reader.ReadToEnd());
        timestamp = Convert.ToBase64String(bytes);
    }

}

// Add the proof to the event
JObject jEvent = JObject.Parse(eventJson);
var proof = new Proof()
{
    signature = encryptedHashBase64,
    timestamp = timestamp,
    verificationMethod = didDocument.verificationMethod.id,
};
jEvent.Add("proof", JsonSerializer.Serialize(proof));

// 6. Verified the event proof/signature and the timestamp token.


public class DIDDocument
{
    public string id { get; set; } = string.Empty;
    public VerificationMethod verificationMethod { get; set; }
}

public class VerificationMethod
{
    public string id { get; set; } = string.Empty;
    public string type { get; set; } = string.Empty;
    public string publicKeyBase64 { get; set; } = string.Empty;
}

public class Proof
{
    public string signature { get; set; } = string.Empty;
    public string verificationMethod { get; set; } = string.Empty;
    public string timestamp { get; set; } = string.Empty;
}