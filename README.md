We added an option to use encrypted CustomerIDs when sending events via the [Optimove SDK](https://docs.optimove.com/optimove-sdk/) (Web or Mobile), to gain an extra level of security. This will prevent other people from sending irrelevant/rogue events to us using plaintext customer IDs (this can be used to generate blasts of event calls that will result in actual campaigns, for example).

This functionality applies only to CustomerIDs that are generated on the server side. 
It does not apply to VisitorIDs that are generated on the client side. 

## **In order to implement:**
1.	Request an encryption key from the Optimove Product Integration Team
2.	Implement CustomerID encryption on the customer server side, as shows in the encryption examples:
* [.NET](https://github.com/optimoveintegrationoptitrack/web-sdk-encryption/tree/master/.NetEncryption/SDKEncryption)
* [JS](https://github.com/optimoveintegrationoptitrack/web-sdk-encryption/tree/master/JSEncryption/EncryptionJSApp)
* [PHP](https://github.com/optimoveintegrationoptitrack/web-sdk-encryption/tree/master/phpEncryption)

**Note**: You can use additional server-side programming languages. The above are only examples.
3.	Use the encrypted CustomerID in all SDK calls implemented
4.	Optimove will perform the decryption and process the events

## **The encryption method we use:**
* Authenticated encryption using CBC encryption with initialization vector and HMAC for the authenticating the message.
* HMAC – Hash-based message authentication code https://en.wikipedia.org/wiki/Hash-based_message_authentication_code 
