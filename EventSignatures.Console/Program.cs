using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using Sodium;
using System.Net.Http.Headers;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

Console.WriteLine("Loading json data...\n");

// Initialize configuration
string jsonPath = "./Data/ObjectEvent.jsonld";
string tsaCertificatePath = "./Timestamping/cacert.pem";
string tsaPath = "./Timestamping/tsa.crt";
string writePath = "C:/temp/signedEvent.jsonld";
string hashUrl = "http://127.0.0.1:5000/hash";

// Initialize services
HttpClient httpClient = new HttpClient();
httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

// Load the json data
var eventJson = File.ReadAllText(jsonPath);

// Genereate the EPCIS Hash
string eventHash = await GenerateEventHash(eventJson);
Console.WriteLine($"Generated Event Hash:\n {eventHash}\n");

// Generate an ED25519 public-private key pair
KeyPair keyPair = PublicKeyBox.GenerateKeyPair();

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
byte[] encryptedHash = PublicKeyBox.Create(eventHash, nonce, keyPair.PrivateKey, keyPair.PublicKey);

// Store the event hash as a base64 string
string nonceBase64 = Convert.ToBase64String(nonce);
string encryptedHashBase64 = Convert.ToBase64String(encryptedHash);

// Generate a timestamp
string timestamp = await GenerateTimeStamp(encryptedHashBase64);

// Add the proof to the event
JObject jEvent = JObject.Parse(eventJson);
var proof = new Proof()
{
    signature = encryptedHashBase64,
    timestamp = timestamp,
    verificationMethod = didDocument.verificationMethod.id,
};
jEvent.Add("proof", JToken.FromObject(proof));

// Write the file for reference
File.WriteAllText(writePath, jEvent.ToString());

// Decrypt the proof value using the public key and compare event hashes
byte[] decryptedData = PublicKeyBox.Open(Convert.FromBase64String(proof.signature), nonce, privateKey, publicKey);
string decryptedHash = Encoding.ASCII.GetString(decryptedData);
Console.WriteLine($"\n[{eventHash}] - Original Hash");
Console.WriteLine($"[{decryptedHash}] - Decrypted Hash\n");

// Validate the timestamp token
TimeStampResponse tsr;
using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(proof.timestamp)))
{
    PemObject tsrPem = new PemReader(new StreamReader(ms)).ReadPemObject();
    tsr = new TimeStampResponse(Convert.FromBase64String(proof.timestamp));

    // Get the certificate used to sign this request
    var store = tsr.TimeStampToken.GetCertificates();
    var collection = store.GetMatches(null);
    var iterator = collection.GetEnumerator();
    iterator.MoveNext();
    X509Certificate tsaCertificate = new X509CertificateParser().ReadCertificate(((X509CertificateStructure)iterator.Current).GetEncoded());

    // Use the cert to validate the time stamp token
    tsr.TimeStampToken.Validate(tsaCertificate);

    // Read the data from the request
    var tsrValidationBytes = tsr.TimeStampToken.TimeStampInfo.GetMessageImprintDigest();
    var tsrEventHash = Convert.ToBase64String(tsrValidationBytes);
    
    // Generate a SHA-512 hash of the expected encrypted hash value to compare to the SHA-512 hash of the encrypted event hash that was time stamped
    Sha512Digest digest = new Sha512Digest();
    byte[] encryptedHashBytes = encryptedHash;
    int readLength = encryptedHashBytes.Length;
    digest.BlockUpdate(encryptedHashBytes, 0, readLength);
    byte[] result = new byte[digest.GetDigestSize()];
    digest.DoFinal(result, 0);
    string computedHash = Convert.ToBase64String(result);
    Console.WriteLine($"[{tsrEventHash}] - TSR Event Hash");
    Console.WriteLine($"[{computedHash}] - Computed Event Hash");

    DateTime timestampTime = tsr.TimeStampToken.TimeStampInfo.GenTime;
    Console.WriteLine("Timestamp Time: " + timestampTime);
}

// Demonstrate how editing the data invalidates the proof

async Task<string> GenerateEventHash(string eventJson)
{
    // Generate the EPCIS Event Hash
    var hashRequest = new HttpRequestMessage(HttpMethod.Post, hashUrl);
    hashRequest.Content = new StringContent(eventJson, Encoding.UTF8, "application/json");
    var response = await httpClient.SendAsync(hashRequest);
    var eventHash = await response.Content.ReadAsStringAsync();
    return eventHash;
}

async Task<string> GenerateTimeStamp(string data)
{
    // Format the byte array to be time stamped
    Sha512Digest digest = new Sha512Digest();
    byte[] dataToTimestamp = Convert.FromBase64String(data);
    int readLength = dataToTimestamp.Length;
    digest.BlockUpdate(dataToTimestamp, 0, readLength);
    byte[] result = new byte[digest.GetDigestSize()];
    digest.DoFinal(result, 0);

    TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
    tsqGenerator.SetCertReq(true); // Request the TSA certificate
    TimeStampRequest tsq = tsqGenerator.Generate(TspAlgorithms.Sha512, result);

    // Convert the timestamp query to bytes
    byte[] tsqBytes = tsq.GetEncoded();

    string timestamp = string.Empty;
    HttpRequestMessage timestampRequest = new HttpRequestMessage(HttpMethod.Post, "https://freetsa.org/tsr");
    using (var stream = new MemoryStream(tsqBytes))
    {
        timestampRequest.Content = new StreamContent(stream);
        timestampRequest.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");
        var timestampResponse = await httpClient.SendAsync(timestampRequest);
        var bytes = await timestampResponse.Content.ReadAsByteArrayAsync();
        timestamp = Convert.ToBase64String(bytes);
    }
    return timestamp;
}

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