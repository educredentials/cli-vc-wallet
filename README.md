# Commandline Verifiable Credential Wallet

A commandline tool that simulates a wallet which can hold and interact with [verifiable credentials](https://www.w3.org/TR/vc-data-model-2.0/)

The wallet is meant as a **tool for develolopers and implementors of verifiable credential services**.

## Components

WIP. Currently there's still just a single command, but once that is working
through the happy path, we will split it up into smaller commands.

Planned commands are:

- [ ] `vc-wallet offer` - given a credential offer, resolves it if necessary, and prints a normalized offer to stdout. Amongst the information is:
   - [x] Whether the offer is by value or by reference
   - [ ] Whether the credential request goes via the Authorization Code Flow or is pre-authorized
   - [ ] Any potential pre-shared secrets, or requirement thereof
   - [ ] The credential type, types or credentials in the offer
   - [x] It returns the issuer url
- [ ] `vc-wallet issuer` - given a normalized offer, or an issuer URL, requests issuer metadata and shows
   - [ ] possible Proof types and algorithms the issuer supports
   - [x] issuers' authorization server if set
   - [ ] issuers' endpoint
   - [ ] issuers' DID
   - [ ] issuers' public key(s)
   - [ ] issuers' supported credential types.
- [ ] `vc-wallet authorize` - given a the url of the authorization server,
   - [x] print the authorization URL to stdout
   - [x] start a local webserver to receive the callback
   - [ ] Allow the user to choose the callback url with host, port and path that the listener will bind to
   - [x] exchange the authorization code for an access token
   - [x] print the resulting access token to stdout on success
   - [x] print the error to stderr on failure
- [x] `vc-wallet proof` - generate and view proof of possession
   - [x] allow the user to provide keypair and DID via commandline or stdin
   - [x] generate a JWT proof of possession for a given credential issuer
   - [x] optionally include a nonce in the proof
   - [x] display the proof contents
   - [x] print the proof JWT to stdout
- [ ] `vc-wallet request` - given a normalized offer and a proof of possession, requests the credential from the issuer
   - [x] require a proof of possession JWT as input
   - [ ] EITHER an access token,
   - [ ] OR a pre-shared secret
   - [x] request the credential from the issuer
   - [x] print the credential to stdout
- [ ] `vc-wallet verify` - given a credential, verifies the proof and the credential
   - [ ] show the user the proof that was sent by the issuer
   - [ ] verify the proof
   - [ ] verify the credential
   - [ ] print the verification results to stdout
- [ ] `vc-wallet present` - given a presentation request, shows the user credentials that can be offered
   - [ ] show the user the presentation request
   - [ ] show the user the credentials that can be offered from a glob, directory or list of credentials in JSON on disk
   - [ ] allow the user to pick a credential to offer
   - [ ] check if the credential can be offered according to the request
   - [ ] show the user the data that will be sent to the verifier
   - [ ] send the proof and credential to the verifier
- [ ] `vc-wallet interactive` - given only a credential offer, walk the user through the entire flow.
   - [ ] On each step, show the user what has been resolved, which calls were made, 
   - [ ] what the next step will be with a prompt to continue or abort.
   - [ ] For each step, ask the user what values and choices they must provide.
   - [ ] Show the user the contents of the final credential and the proof.

## TODOs

Other TODOs and fixes, aside from the abovementioned commands and features:

- [ ] Move `issuer_state` from Credential Request to Authorization Request.
- [ ] Make `issuer_state` required *when it is in the offer*.
- [x] Move KEYPAIR and DIDKEY to commandline arguments - implemented via the `proof` command which accepts these as arguments or via stdin
- [ ] Have `issuer-metadata` try several URLS and pick the first one that resolves rather than only .well-known/openid-credential-issuer

## Design goals and principles

* A user should be able to follow the flow and steps very clearly.
* Any options or choices should be left to the user to choose.
* Any error or possible mistake should lead to immediate termination with clear errors.
* Any error that indicates a misconfigured issuer, or other service, but that
  can be recovered from, should be logged and the user prompted with options to
  fix it.
* Third party libraries should be wrapped in a way that they adhere to these above design goals.
* Results should be printed to stdout as plain text or json.
* Commands that take an input, should take it from stdin.
* The wallet is entirely stateless. Any state needed for signing, listing, requesting must be passed into the commands as input. 
* We support only the latest versions of specs.

## Non Design goals

* It is not a benchmark or test suite to check compliance with specifications.
* It does not implement all options and all features, but it may.
* Features are only implemented if someone needs them, not just because a spec
  says that something (optional) could be considered.
* There is no secure storage, nor any data encryption. 
* We don't generate keys, certificates, JWTs, JWKs or DIDs. We assume the user has them.

## To be decided on

* Do we want to interactivly prompt a user, or rather take commandline arguments?
* Do we want multiple small that can be piped and if so, how do we deal with
  the more complex flows that would chain together these flows conditionally? Maybe offer both?
* Do we want to support all possible signing algorithms, and proof types or only the most common ones?
* Do we want to support all possible flows, or only the most common ones?
* Do we want to support all possible credential types, or only the most common ones?
* Do we want to add checks or limations to [High Assurance Interoperability Profile (HAIP)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)?
* Do we want to add checks or limitations to [Decentralized Identity Interoperability Profile (DID)](https://fidescommunity.github.io/DIIP/)

## TODOs, planned features

* [ ] Resolve and "normalize" the [offer-by-reference to a full offer](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-sending-credential-offer-by-).
* [ ] Determine wether we have an authorized code flow or a pre-authorized flow.
* [ ] Visualize the progress of the flow in a sequence diagram or similar in the terminal.
* [ ] Determine the issuers capabilities wrt to proof types and algorithms, fail if we can't provide the right proof, and offer cli-options to provide one proof when we support more.
* [ ] [Deferred Credential Requests](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-respons)
- [ ] [Encrypted Credential Responses](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2-16)
- [ ] Implement VCs using JSON-LD
- [ ] Implement VCs using ISO mDL
- [ ] Implement VCs using IETF SD-JWT VC

## Persistence

The wallet is stateless, but you might want to store some data, like keys, certificates, JWTs, JWKs or DIDs.

We currently use environment variables to store this data. In future this will be moved to commmandline arguments.

### Env file

You can use the provided .env.template: Copy it to .env and fill in the values. 
The .env file is ignored by git, so you can safely store your secrets there.

**NOTE:** We do not load the .env file automatically, you have to do that yourself. Use
e.g. [zenv](https://github.com/numToStr/zenv) or any runner that can load .env
files.

### Keys, Certificates, JWT, JWK and DID.

When retrieving a Verifiable Credential, the wallet will provide a Proof of Possession and key
material to the issuer.

The [spec allows several types and structures](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request). We limit ourselves to the following:

* Only one proof, we don't support multiple proofs.
* Only the [JWT proof type](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types).
* Key generated with ed25519 algorithm.
* A did:key DID.

#### Generating keypair and did:key

1. Install [didkit](https://www.sprucekit.dev/verifiable-digital-credentials/didkit/installation)
2. Generate a key with didkit
    ```bash
    didkit key generate ed25519 > keys/key.json
    ```
3. Convert the key to a did:key DID
    ```bash
    didkit key to did --key-path keys/key.json > keys/did.txt
    ```
4. Store the keypair json and the did:key for use with the commands.
   
#### Using the proof command

The `proof` command generates a JWT proof of possession that demonstrates control of a cryptographic key:

```bash
# Generate a proof using command-line arguments
cli-vc-wallet proof \
  --credential-issuer "https://issuer.example.com" \
  --keypair "$(cat keys/key.json)" \
  --did "$(cat keys/did.txt)"

# Generate a proof with a nonce
cli-vc-wallet proof \
  --credential-issuer "https://issuer.example.com" \
  --keypair "$(cat keys/key.json)" \
  --did "$(cat keys/did.txt)" \
  --nonce "challenge-from-issuer"

# Read keypair from stdin
cat keys/key.json | cli-vc-wallet proof \
  --credential-issuer "https://issuer.example.com" \
  --keypair - \
  --did "$(cat keys/did.txt)"
```

The proof output can be piped to the `request` command:

```bash
# Generate proof and use it in credential request
PROOF=$(cli-vc-wallet proof \
  --credential-issuer "https://issuer.example.com" \
  --keypair "$(cat keys/key.json)" \
  --did "$(cat keys/did.txt)")

cli-vc-wallet request \
  --configuration-id "UniversityDegreeCredential" \
  --credential-issuer "https://issuer.example.com" \
  --credential-endpoint "https://issuer.example.com/credential" \
  --proof "$PROOF" \
  --access-token "your-access-token"
```

**NOTE:** The `request` command now requires a proof parameter. You must generate the proof separately using the `proof` command before making a credential request.

TODO: implement arguments to pass the keypair and did:key as input to the commands.
NOTE: The wallet is stateless, so the keypair and did:key must be provided as input to the commands.
      For now, we pass them, using ENV vars.
