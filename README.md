# aotp-tools

Set of sub command to do stuff with OTP

## qr-dump

take a QR picture as argument, and dump the parameters and secret in base32

Supported input:

* otpauth qr code
* otpauth-migration qr code (export format for google authenticator)

> aotp-tools qr-dump my-qr-code-image.png
