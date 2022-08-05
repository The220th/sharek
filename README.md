# sharek

`sharek` позволяет обмениваться файлом напрямую с шифрованием `AES256-CBC`. Так как используются linux-api, то собрать можно только для ОС `GNU/Linux`. После приёма файла будет сверен его `SHA-256` хэш. 

Шифрование взято и "завраплено" [отсюда](https://github.com/SergeyBel/AES). Хеширование взято и "завраплено" [отсюда](https://github.com/B-Con/crypto-algorithms). 

# Зависимости

Нет

# Компиляция

В директории, где есть файл `Makefile` выполните команду:

``` bash
> make
```

Появится файл `./sharek`. Его дальше и нужно запускать.

# Использование

После компилирования или [скачивания релиза](https://github.com/The220th/sharek/releases) нужно выбрать, кто будет передатчиком (параметр `out`), а кто будет приёмником (параметр `in`). Также нужно выбрать кто будет клиентом (`out-c` или `in-c`), а кто будет сервером (`out-s` или `in-s`). Всегда сначала запускается сервер, а потом клиент.

Для удобства можно исполняемый файл перенести в директорию `~/.local/bin/`, предворительно убедившись, что директория есть в PATH: `~/.bashrc`:` export PATH=$PATH:/home/user/.local/bin/`.

## Передатчик (transmitter)

Передатчик передаёт файл приёмнику.

``` bash
# Если передатчик клиент:
> sharek out-c {ip} {port} {password} {filename}
# {ip} - ip-address приёмника (сервера)
# {port} - порт приёмника (сервера)
# {password} - пароль для шифрования AES256-CBC
# {filename} - файл, который нужно передать

# Если передатчик сервер:
> sharek out-s {port} {password} {filename}
# {port} - порт, на который будет забинжен сервер (передатчик)
# {password} - пароль для шифрования AES256-CBC
# {filename} - файл, который нужно передать
```

По умолчанию передатчик коннектится к приёмнику как клиент.

``` bash
> sharek out {ip} {port} {password} {filename}

# {ip} - ip-address приёмника (сервера)
# {port} - порт приёмника (сервера)
# {password} - пароль для шифрования AES256-CBC
# {filename} - файл, который нужно передать
```

## Приёмник (receiver)

Приёмник принимает файл от передатчика.

``` bash
# Если приёмник сервер:
> sharek in-s {port} {password} {filename}
# {port} - порт, на который будет забинжен сервер (приёмник)
# {password} - пароль для шифрования AES256-CBC
# {filename} - как будет называться принятый файл

# Если приёмник клиент:
> sharek in-c {ip} {port} {password} {filename}
# {ip} - ip-address передатчика (сервера)
# {port} - порт передатчика (сервера)
# {password} - пароль для шифрования AES256-CBC
# {filename} - как будет называться принятый файл
```

Приёмник выступает сервером. К нему коннектится передатчик. 

``` bash
> sharek in {port} {password} {filename}
# {port} - порт, на который будет забинжен сервер (приёмник)
# {password} - пароль для шифрования AES256-CBC
# {filename} - как будет называться принятый файл
```