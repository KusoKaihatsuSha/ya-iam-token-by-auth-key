# ya-iam-token-by-auth-key
### Simple helper for generate IAM yandex-cloud token, using auth creds.
### !!! special for __iam.api.cloud.yandex.net__

#### First of all go to your account:

> Service __accounts__ -->

> Create __new key__ -->

> Create authorized key. To request IAM tokens -->

> Create -->

> Download file with keys --> 

#### FLAGS

> -token="YC_TOKEN2"

Set token name(key). Default is "YC_TOKEN"

> -raw

Print without 'export' text. 

If **'-raw=true'** or **'-raw'**, print only IAM token

Else you may use with eval(or alternative)

> -from="authorized_key.json" 

Set filepath with keys

> -to="IAM_token_output.txt"

For saving IAM to filepath.


#### USING FOR ADD TO ENVIRONMENT 

##### Windows: 

```shell
For /f "delims=" %A in ('ya-iam-token-by-auth-key.exe -from=keys/authorized_key.json') do call %A
```

##### Linux:

```shell
eval $(./ya-iam-token-by-auth-key -from=keys/authorized_key.json)
```

##### Notes:

You may download binary file (using **wget** from this repo, for exapmle).

Put/Create file **"authorized_key.json"** if same folder with EXE/BINARY file and run app without flags.

```shell
For /f "delims=" %A in ('ya-iam-token-by-auth-key.exe') do call %A
```

```shell
eval $(./ya-iam-token-by-auth-key)
```
