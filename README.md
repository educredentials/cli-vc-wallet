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

## To be decided on

* Do we want to interactivly prompt a user, or rather take commandline arguments?
* Do we want multiple small that can be piped and if so, how do we deal with
  the more complex flows that would chain together these flows conditionally? Maybe offer both?
