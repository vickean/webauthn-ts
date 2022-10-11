# WebAuthn Typescript

### Overview

_The WebAuthn specification has two interesting parts for Web Developers:_

-   Registering a new user in your app and verifying logins of said user. In the code sample, you can find the server-side implementation of these steps in src -> authentication -> signup.ts / verify.ts.
-   All client-side (web browser) related implementation can be found in pages -> webauthn.js.
-   Click through these files and read the comments to learn about the general implementation flow.
-   If you want to dig deeper, many of the comments already have references to the part of the specification that they are implementing.

### Resources

-   [WebAuthn Guide](https://webauthn.guide/) by DUO.
-   [WebAuthn specification](https://w3c.github.io/webauthn/) in W3C.

### Glossary:

-   [Installation](#installation)
-   [Working With This Project](#working-with-this-project)

## Installation

You will need to perform the following on your development machine:

1. Node.js (v16.4.0 is recommended) and NPM (see <https://nodejs.org/en/download/package-manager/>)
2. Clone this repo
3. Run `npm install` from the project root folder
4. Copy [.env.example](.env.example) file and rename into `.env`. Change the variables wherever necessary.
5. Remap `localhost` to `sora.dev.ringgitplus.com` to match the SSL certs for testing via editing the `hosts` file.
6. Add `sora.dev.ringgitplus.com` cert and key files in the `/src/ssl` folder.
7. Run `npm run start`s

## Working With This Project

|  Command   | Description                                                                                                                                          |
| :--------: | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
|  `start`   | Runs the app in the development mode. Open [https://sora.dev.ringgitplus.com:4430](https://sora.dev.ringgitplus.com:4430) to view it in the browser. |
|   `css`    | Run the CLI tool to scan your template files for classes and build your CSS. Watches for any css changes if kept running.                            |
| `prettify` | Formatting is done on covered files based on prettier config.                                                                                        |

## Integration Notes

```
Ideally, there should only be one form page that handles registration/login. This means that if the user intends to the register, they will need to fill in the Email and PIN and submit the form but if they want to login, they should only need to fill in the Email and submit.

In the current state of the POC, I've left the register and login pages separate in the interest of time. Therefore, to reach the login page, you will need to "register" first then reload the page to reach the login page. Apologies for the inconvenience caused.

- Victor K.
```
