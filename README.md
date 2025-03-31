# Commandline Verifiable Credential Wallet

A commandline tool that simulates a wallet which can hold and interact with [verifiable credentials](https://www.w3.org/TR/vc-data-model-2.0/)

The wallet is meant as a **tool for develolopers and implementors of verifiable credential services**.

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

## TODOs, planned features

* [ ] Resolve and "normalize" the [offer-by-reference to a full offer](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-sending-credential-offer-by-).
* [ ] Determine wether we have an authorized code flow or a pre-authorized flow.
* [ ] Visualize the progress of the flow in a sequence diagram or similar in the terminal.
* [ ] Determine the issuers capabilities wrt to proof types and algorithms, fail if we can't provide the right proof, and offer cli-options to provide one proof when we support more.

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
4. Store the keypair json and the did:key in ENV vars, so the wallet can use them.
    4.1. as ENV vars
    ```bash
    export KEYPAIR=$(cat keys/key.json)
    export DIDKEY=$(cat keys/did.txt)
    ```
  4.2. in .env file
    ```bash
    echo "KEYPAIR=$(cat keys/key.json | tr -d \"\n")" >> .env
    echo "DIDKEY=$(cat keys/did.txt)" >> .env
    ```

TODO: implement arguments to pass the keypair and did:key as input to the commands.
NOTE: The wallet is stateless, so the keypair and did:key must be provided as input to the commands.
      For now, we pass them, using ENV vars.
