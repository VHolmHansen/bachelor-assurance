# Implementation of FAEST
This is our iteration6 implementation. 
This contains an implementation that works for all 6 different variants of FAEST-$\lambda$.
## Tests
There is a tests folder located, that contains all our tests. 
For the FAEST-128s there is a few more tests. 
We have written for this iteration tests, for almost all the methods/files that we have.
For all variants there are tests for checking that sign-verify runs, and also a testvector for a signature from the C reference implementation.
## How to run
To run the different tests there is one important kaviat. 
In the Cargo.toml file in the bottom there is:
```
[features] 
lambda_128s = [] # lambda = 128, tau = 11, ell = 1600
lambda_128f = [] # lambda = 128, tau=16, ell = 1600
lambda_192s = [] # lambda = 192, tau = 16, ell = 3264
lambda_192f = [] # lambda = 192, tau=24, ell = 3264
lambda_256s = [] # lambda = 256, tau = 22, ell = 4000
lambda_256f = [] # lambda = 256, tau = 32, ell = 4000
default = ["lambda_128s"]
```
When changing between versions, then inside the toml, the default has to be changed to the wanted version. 
At the same time inside src/utils/constants.rs, at the top the parameters:
- Lambda
- Tau
- Ell

Has to be updated according to the specs from the Cargo.toml file. 
This is because inside our different test files we set some flags:
```
#[cfg(all(test, feature = "lambda_128s"))]
#[cfg(all(test, feature = "lambda_192s"))]
#[cfg(all(test, feature = "lambda_256s"))]
#[cfg(all(test, feature = "lambda_128f"))]
#[cfg(all(test, feature = "lambda_192f"))]
#[cfg(all(test, feature = "lambda_256f"))]
```
Regarding which version is being used.
This is so the compiler only compiles the version that at, that moment will work for the constants in src/utils/constants.rs